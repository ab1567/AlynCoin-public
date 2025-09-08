FROM ubuntu:22.04

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY build/alyncoin /usr/local/bin/alyncoin

EXPOSE 1567 15671
ENTRYPOINT ["/usr/local/bin/alyncoin"]
