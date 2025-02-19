FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/snusbase-connector

# Install system dependencies
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    cd /opt/snusbase-connector && \
    pip install --upgrade pip && \
    pip3 install --no-cache-dir pycti requests pyyaml stix2 python-magic schedule && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["sh","/entrypoint.sh"]
