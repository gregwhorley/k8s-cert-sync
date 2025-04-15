FROM --platform=linux/amd64 alpine:latest

RUN apk update && \
    apk upgrade --no-cache && \
    apk add --no-cache python3 py3-pip py3-kubernetes py3-cryptography py3-boto3 && \
    ln -sf python3 /usr/bin/python && \
    rm -rf /var/cache/apk/*

RUN adduser -D -h /opt appuser

WORKDIR /opt

COPY --chown=appuser:appuser import_certs_acm.py .

RUN chown -R appuser:appuser /opt

USER appuser

CMD ["python", "import_certs_acm.py"]
