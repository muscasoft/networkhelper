#!/usr/bin/env python3
import datetime
import docker
import http.client
import json
import os
import re
import signal
import socket
import sys
#import urllib.parse
#import yaml

from docker.models.containers import Container 
from types import FrameType
from typing import Any, cast, Dict, Iterable, List, Optional

# --- Constants ---
LABEL_NAMESPACE = "dockerhelper"
LABEL_ACTION_CONNECT = "networkconnect"
LABEL_ACTION_LOGIN = "login"
LABEL_SEPARATOR = "."  # the dot between namespace and action
LABEL_NAMESPACE_CONNECT = f"{LABEL_NAMESPACE}{LABEL_SEPARATOR}{LABEL_ACTION_CONNECT}{LABEL_SEPARATOR}"
LABEL_NAMESPACE_LOGIN = f"{LABEL_NAMESPACE}{LABEL_SEPARATOR}{LABEL_ACTION_LOGIN}{LABEL_SEPARATOR}"
ACTION_START = "start"
ACTION_KILL = "kill"
ATTRS_ACTOR = "Actor"
ATTRS_ATTRIBUTES = "Attributes"
ATTRS_NETWORK_SETTINGS = "NetworkSettings"
ATTRS_NETWORKS = "Networks"
CONTAINER = "container"
EVENT_ACTION = "Action"
EVENT_TYPE = "Type"
LOG_PREFIX = "[docker-helper]"
LOG_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

CADDY_SOCKET = os.getenv("CADDY_SOCKET", "/var/run/caddy/admin.sock") 
AUTHELIA_URL = os.getenv("AUTHELIA_URL", "http://authelia:9091")
CADDY_API_ERROR_PREFIX = "Caddy API error: "

AF_UNIX: int = socket.AF_UNIX # pyright: ignore reportUnknownMemberType]
SOCK_STREAM: int = socket.SOCK_STREAM
DEFAULT_AUTHELIAPOLICY = os.getenv("DEFAULT_AUTHELIAPOLICY", "one_factor")

# --- Centralized log messages ---
LOG_MESSAGES = {
    "starting": "Starting, processing existing containers...",
    "initial connect": "Initial connect: {container}: {target} to {network}",
    "initial login": "Initial login: {container}: set login for domain {domain} at {container_url} with policy {policy} ",
    "listening": "Listening for container events...",
    "event start network": "Event: {container} start: connect {target} to {network}",
    "event kill network": "Event: {container} kill: disconnect {target} from {network}",
    "event start login": "Event: {container} start: set login for domain {domain} at {container_url} with policy {policy}",
    "event kill login": "Event: {container} kill: remove login for domain {domain}",
    "stopping": "Docker-helper stopping - cleaning up...",
    "cleanup connect": "Cleanup: {container}: disconnect {target} from {network}",
    "cleanup login": "Cleanup: {container}: remove login for domain {domain}",
    "cleanup done": "Cleanup done. Exiting.",
    "connecting": "Connecting {container} to {network}",
    "already connected": "{container} already connected to {network}",
    "error connect": "Error connecting {container} to {network}: {error}",
    "disconnecting": "Disconnecting {container} from {network}",
    "not connected": "{container} was not connected to {network}",
    "error disconnect": "Error disconnecting {container} from {network}: {error}",
    "login set": "Set login for domain {domain} (policy={policy}, url={url})",
    "login removed": "Removed login for domain {domain}",
    "no container_url login set": "Error setting login for {container}: no container_url specified for {domain}", 
    "error login set": "Error setting login for {domain}: {error}", 
    "error login remove": "Error removing login for {domain}: {error}"
}

# --- Docker client ---
client = docker.from_env()

def log(msg: str):
    """Simple timestamped logger using centralized format."""
    now = datetime.datetime.now().strftime(LOG_TIMESTAMP_FORMAT)
    print(f"[{now}] {LOG_PREFIX} {msg}", flush=True)

def connect_container_to_network(container_name: str, network_name: str):
    """Connect a container to a Docker network if not already connected."""
    try:
        network = client.networks.get(network_name)
        container = client.containers.get(container_name)
        connected_networks = container.attrs[ATTRS_NETWORK_SETTINGS][ATTRS_NETWORKS].keys()
        if network_name not in connected_networks:
            log(LOG_MESSAGES["connecting"].format(container=container_name, network=network_name))
            network.connect(container) # type: ignore
        else:
            log(LOG_MESSAGES["already connected"].format(container=container_name, network=network_name))
    except Exception as e:
        log(LOG_MESSAGES["error connect"].format(container=container_name, network=network_name, error=e))

def do_connect_container_to_network(logmessage: str, container_name: str,  label_key: str, label_value: str):
    target_container = label_key[len(LABEL_NAMESPACE_CONNECT):]
    log(logmessage.format(container=container_name, target=target_container, network=label_value))
    connect_container_to_network(target_container, label_value)

def disconnect_container_from_network(container_name: str, network_name: str):
    """Disconnect a container from a Docker network if connected."""
    try:
        network = client.networks.get(network_name)
        container = client.containers.get(container_name)
        connected_networks = container.attrs[ATTRS_NETWORK_SETTINGS][ATTRS_NETWORKS].keys()
        if network_name in connected_networks:
            log(LOG_MESSAGES["disconnecting"].format(container=container_name, network=network_name))
            network.disconnect(container)
        else:
            log(LOG_MESSAGES["not connected"].format(container=container_name))
    except Exception as e:
        log(LOG_MESSAGES["error disconnect"].format(container=container_name, network=network_name, error=e))

def do_disconnect_container_from_network(logmessage: str, container_name: str, label_key: str, label_value: str):
    target_container = label_key[len(LABEL_NAMESPACE_CONNECT):]
    log(logmessage.format(container=container_name, target=target_container, network=label_value))
    connect_container_to_network(target_container, label_value)

class UnixSocketHTTPConnection(http.client.HTTPConnection):
    """Return an HTTPConnection object that communicates with Caddy over a Unix socket."""
    class UnixSocketConnection(http.client.HTTPConnection):
        unix_socket_path: str
        sock: Optional[socket.socket] 

        def __init__(self, path: str):
            super().__init__('localhost') # host is niet relevant
            self.unix_socket_path = path
            self.sock = None 

        def connect(self) -> None:
            sock: socket.socket = socket.socket(AF_UNIX, SOCK_STREAM)
            sock.connect(self.unix_socket_path)
            self.sock = sock            

    caddy_socket = os.getenv("CADDY_SOCKET")
    if not caddy_socket:
        raise RuntimeError("CADDY_SOCKET is not set")

def build_caddy_config(domain: str, container_url: str) -> Dict[str, Any]:
    """Return Caddy JSON config with placeholders filled."""
    forward_auth: Dict[str, Any] = {
        "handler": "forward_auth",
        "uri": "/api/authz/forward-auth",
        "upstreams": [{"dial": AUTHELIA_URL}],
        "copy_headers": ["Remote-User", "Remote-Groups", "Remote-Email", "Remote-Name"],
    }

    reverse_proxy: Dict[str, Any] = {
        "handler": "reverse_proxy",
        "upstreams": [{"dial": container_url}],
    }

    return {
        "apps": {"http": {"servers": {"srv0": {"routes": [{
            "match": [{"host": [domain]}],
            "handle": [{"handler": "subroute", "routes": [
                {"handle": [forward_auth]},
                {"handle": [reverse_proxy]}
            ]}]
        }]}}}}}

def set_login_for_domain(domain: str, policy: str, container_url: str) -> None:
    """Add a login configuration for a domain to Caddy via Unix socket."""
    try:
        caddy_config = build_caddy_config(domain, container_url)
        conn = UnixSocketHTTPConnection(CADDY_SOCKET)
        body_str = json.dumps(caddy_config)
        conn.request(
            "POST",
            "/config/",
            body=body_str.encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        response = conn.getresponse()
        if response.status not in (200, 201):
            raise RuntimeError(f"{CADDY_API_ERROR_PREFIX}{response.status} {response.reason}")
        conn.close()
        log(LOG_MESSAGES["login set"].format(domain=domain, policy=policy, url=container_url))
    except Exception as e:
        log(LOG_MESSAGES["error login set"].format(domain=domain, error=e)) 

def remove_login_for_domain(domain: str) -> None:
    """Remove login configuration for a domain from Caddy."""
    try:
        conn = UnixSocketHTTPConnection(CADDY_SOCKET)

        # Get current config
        conn.request("GET", "/config/")
        response = conn.getresponse()
        config = json.loads(response.read().decode())
        conn.close()

        # Filter routes that NOT corresponds with the  domain
        routes = config.get("apps", {}).get("http", {}).get("servers", {}) \
                      .get("srv0", {}).get("routes", [])
        new_routes = [r for r in routes if domain not in [h.get("host")[0] 
                                                          for h in r.get("match", [])]]

        # Update config
        config["apps"]["http"]["servers"]["srv0"]["routes"] = new_routes

       # Post back to Caddy
        conn = UnixSocketHTTPConnection(CADDY_SOCKET)
        body_str = json.dumps(config)
        conn.request("POST",
                     "/config/",
                     body=body_str.encode("utf-8"),
                     headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        if response.status not in (200, 201):
            raise RuntimeError(f"{CADDY_API_ERROR_PREFIX}{response.status} {response.reason}")
        conn.close()
        log(LOG_MESSAGES["login removed"].format(domain=domain))  
    except Exception as e:
        log(LOG_MESSAGES["error login remove"].format(domain=domain, error=e))

def do_set_login_for_domain(logmessage: str, container_name: str, labels: Dict[str, str]) -> None:
    domain = labels.get(f"{LABEL_NAMESPACE_LOGIN}{LABEL_SEPARATOR}domain")
    if not domain:
        return

    # strip protocol if present**
    domain = re.sub(r"^https?://", "", domain)

    container_url = labels.get(f"{LABEL_NAMESPACE_LOGIN}{LABEL_SEPARATOR}container_url")
    if not container_url:
        log(LOG_MESSAGES["no container_url login set"].format(container=container_name, domain=domain))
        return

    policy = labels.get(f"{LABEL_NAMESPACE_LOGIN}{LABEL_SEPARATOR}policy")
    if not policy:
        policy = DEFAULT_AUTHELIAPOLICY

    log(logmessage.format(container=container_name, domain=domain, container_url=container_url, policy=policy))
    set_login_for_domain(domain, policy, container_url)

def do_remove_login_for_domain(logmessage: str, container_name: str, labels: Dict[str, str]) -> None:
    domain = labels.get(f"{LABEL_NAMESPACE_LOGIN}{LABEL_SEPARATOR}domain")
    if not domain:
        return
    log(logmessage.format(container=container_name))
    remove_login_for_domain(domain)

def process_labels_from_event(labels: Dict[str, str], action: str):
    """Process container labels and perform connect/disconnect actions."""
    container_name = labels.get("name")
    if not container_name:
        return

    # process connect labels for both start and kill
    connect_labels = {k: v for k, v in labels.items() if k.startswith(LABEL_NAMESPACE_CONNECT)}
    for key, value in connect_labels.items():
        if action == ACTION_START:
            do_connect_container_to_network(LOG_MESSAGES["event start network"], container_name, key, value)
        elif action == ACTION_KILL:
            do_disconnect_container_from_network(LOG_MESSAGES["event kill network"], container_name, key, value)

    # process login labels for both start and kill
    login_labels = {k: v for k, v in labels.items() if k.startswith(LABEL_NAMESPACE_LOGIN)}
    if action == ACTION_START:
        do_set_login_for_domain(LOG_MESSAGES["event start login"], container_name, login_labels)
    elif action == ACTION_KILL:
        do_remove_login_for_domain(LOG_MESSAGES["event kill login"], container_name, login_labels)

def process_existing_containers(connect: bool = True):
    """Process all currently running containers based on labels."""
    containers = cast(List[Container], client.containers.list()) # type: ignore
    for container in containers:
        container_name = cast(str, container.attrs.get("name"))
        labels = cast(Dict[str, str], container.labels or {}) # type: ignore

        # process connect labels for both start and kill
        connect_labels = {k: v for k, v in labels.items() if k.startswith(LABEL_NAMESPACE_CONNECT)}
        for key, value in connect_labels.items():
            if connect:
                do_connect_container_to_network(LOG_MESSAGES["initial connect"], container_name, key, value)
            else:
                do_disconnect_container_from_network(LOG_MESSAGES["cleanup connect"], container_name, key, value)

        # also echo login labels on startup
        login_labels = {k: v for k, v in labels.items() if k.startswith(LABEL_NAMESPACE_LOGIN)}
        if connect:
            do_set_login_for_domain(LOG_MESSAGES["initial_login"], container_name, login_labels)
        else:
            do_remove_login_for_domain(LOG_MESSAGES["cleanup login"], container_name, login_labels)

def cleanup_and_exit(signum: int, frame: Optional[FrameType]):
    """Handle SIGINT/SIGTERM: cleanup networks before exit."""
    _ = frame  # markeer als gebruikt zodat typechecker niet klaagt
    log(LOG_MESSAGES["stopping"])
    process_existing_containers(connect=False)
    log(LOG_MESSAGES["cleanup done"])
    sys.exit(0)

def main():
    """Main loop: setup signal handlers, process existing containers, listen to Docker events."""
    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    log(LOG_MESSAGES["starting"])
    process_existing_containers(connect=True)

    # Listen for container start/kill events
    log(LOG_MESSAGES["listening"])
    events_iter = cast(Iterable[Dict[str, Any]], client.events(decode=True)) # type: ignore
    for event in events_iter:
        if event.get(EVENT_TYPE) == CONTAINER:
            action = event.get(EVENT_ACTION)
            if action in (ACTION_START, ACTION_KILL):
                attrs = event.get(ATTRS_ACTOR, {}).get(ATTRS_ATTRIBUTES, {})
                process_labels_from_event(attrs, action)

if __name__ == "__main__":
    main()
