FROM python:3.12-slim
ARG AGENTSEAL_VERSION=0.8.0
RUN pip install --no-cache-dir agentseal==${AGENTSEAL_VERSION}
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
