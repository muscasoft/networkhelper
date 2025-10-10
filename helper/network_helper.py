#!/usr/bin/env python3
import datetime
import docker
import os
import signal
import sys
import yaml

# --- Constants ---
LABEL_NAMESPACE = "networkhelper"
LABEL_ACTION_CONNECT = "connect"
LABEL_SEPARATOR = "."  # the dot between namespace and action
LABEL_NAMESPACE_CONNECT = f"{LABEL_NAMESPACE}{LABEL_SEPARATOR}{LABEL_ACTION_CONNECT}{LABEL_SEPARATOR}"
ACTION_START = "start"
ACTION_KILL = "kill"
ATTRS_ACTOR = "Actor"
ATTRS_ATTRIBUTES = "Attributes"
ATTRS_NETWORK_SETTINGS = "NetworkSettings"
ATTRS_NETWORKS = "Networks"
CONTAINER = "container"
EVENT_ACTION = "Action"
EVENT_TYPE = "Type"
LOG_PREFIX = "[network-helper]"
LOG_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

# --- Centralized log messages ---
LOG_MESSAGES = {
    "starting": "Starting, processing existing containers...",
    "initial_connect": "Initial connect: {container}: {target} to {network}",
    "listening": "Listening for container events...",
    "event_start": "Event: {container} start: connect {target} to {network}",
    "event_kill": "Event: {container} kill: disconnect {target} from {network}",
    "stopping": "Network-helper stopping - cleaning up...",
    "cleanup": "Cleanup: {container}: disconnect {target} from {network}",
    "cleanup_done": "Cleanup done. Exiting.",
    "connecting": "Connecting {container} to {network}",
    "already_connected": "{container} already connected to {network}",
    "error_connect": "Error connecting {container} to {network}: {error}",
    "disconnecting": "Disconnecting {container} from {network}",
    "not_connected": "{container} was not connected to {network}",
    "error_disconnect": "Error disconnecting {container} from {network}: {error}"
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
            network.connect(container)
        else:
            log(LOG_MESSAGES["already_connected"].format(container=container_name, network=network_name))
    except Exception as e:
        log(LOG_MESSAGES["error_connect"].format(container=container_name, network=network_name, error=e))

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
            log(LOG_MESSAGES["not_connected"].format(container=container_name))
    except Exception as e:
        log(LOG_MESSAGES["error_disconnect"].format(container=container_name, network=network_name, error=e))

def process_labels_from_event(attrs, action):
    """Process container labels and perform connect/disconnect actions."""
    container_name = attrs.get("name")
    labels = {k: v for k, v in attrs.items() if k.startswith(LABEL_NAMESPACE_CONNECT)}
    if not container_name or not labels:
        return

    for key, value in labels.items():
        target_container = key[len(LABEL_NAMESPACE_CONNECT):]
        if action == ACTION_START:
            log(LOG_MESSAGES["event_start"].format(container=container_name, target=target_container, network=value))
            connect_container_to_network(target_container, value)
        elif action == ACTION_KILL:
            log(LOG_MESSAGES["event_kill"].format(container=container_name, target=target_container, network=value))
            disconnect_container_from_network(target_container, value)

def process_existing_containers(connect=True):
    """Process all currently running containers based on labels."""
    for container in client.containers.list():
        labels = container.labels or {}
        for key, value in labels.items():
            if key.startswith(LABEL_NAMESPACE_CONNECT):
                target_container = key[len(LABEL_NAMESPACE_CONNECT):]
                if connect:
                    log(LOG_MESSAGES["initial_connect"].format(container=container.name, target=target_container, network=value))
                    connect_container_to_network(target_container, value)
                else:
                    log(LOG_MESSAGES["cleanup"].format(container=container.name, target=target_container, network=value))
                    disconnect_container_from_network(target_container, value)

def cleanup_and_exit(signum, frame):
    """Handle SIGINT/SIGTERM: cleanup networks before exit."""
    log(LOG_MESSAGES["stopping"])
    process_existing_containers(connect=False)
    log(LOG_MESSAGES["cleanup_done"])
    sys.exit(0)

def main():
    """Main loop: setup signal handlers, process existing containers, listen to Docker events."""
    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    log(LOG_MESSAGES["starting"])
    process_existing_containers(connect=True)

    # Listen for container start/kill events
    log(LOG_MESSAGES["listening"])
    for event in client.events(decode=True):
        if event.get(EVENT_TYPE) == CONTAINER:
            action = event.get(EVENT_ACTION)
            if action in (ACTION_START, ACTION_KILL):
                attrs = event.get(ATTRS_ACTOR, {}).get(ATTRS_ATTRIBUTES, {})
                process_labels_from_event(attrs, action)

if __name__ == "__main__":
    main()
