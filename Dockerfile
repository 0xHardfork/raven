FROM python:3.11-alpine

WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata bash curl

COPY scripts/requirements.txt /app/scripts/requirements.txt
RUN pip install --no-cache-dir -r /app/scripts/requirements.txt

COPY bin/raven-linux-amd64 /app/raven
COPY scripts/ /app/scripts/
COPY migrations/ /app/migrations/
COPY configs/config.yaml /app/configs/config.yaml

RUN chmod +x /app/raven /app/scripts/*.py

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/app/raven"]
CMD ["watch"]
