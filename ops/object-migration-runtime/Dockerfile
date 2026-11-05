FROM ubuntu:24.04
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates libssl3t64 libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*
COPY --chmod=0555 migrate-conversation-objects /usr/local/bin/migrate-conversation-objects
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/migrate-conversation-objects"]
