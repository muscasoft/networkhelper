# Use Python slim image
FROM python:3.12-alpine

# Set working directory
WORKDIR /app

# Install dependencies at build time
RUN pip install --upgrade pip --root-user-action=ignore && \
    pip install docker pyyaml --root-user-action=ignore

# Copy the network helper script
COPY ./network_helper.py /network_helper.py

# Run the helper
CMD ["python", "/network_helper.py"]
