# BIND9 DNS Server target for fuzzing
# Runs a real BIND9 instance with a local zone configured
# Port 53/udp exposed for the fuzzer to hit

FROM ubuntu:22.04

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        bind9 \
        bind9utils \
        dnsutils \
        procps \
    && rm -rf /var/lib/apt/lists/*

# Copy configuration
COPY named.conf      /etc/bind/named.conf
COPY named.conf.local /etc/bind/named.conf.local
COPY db.fuzz.local   /etc/bind/db.fuzz.local

# Verify config on build
RUN named-checkconf /etc/bind/named.conf && \
    named-checkzone fuzz.local /etc/bind/db.fuzz.local

EXPOSE 53/udp
EXPOSE 53/tcp

CMD ["/usr/sbin/named", "-g", "-c", "/etc/bind/named.conf", "-u", "bind"]
