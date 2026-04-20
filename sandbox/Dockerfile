FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    strace \
    ltrace \
    file \
    binutils \
    python3 \
    python3-pip \
    nodejs \
    npm \
    net-tools \
    tcpdump \
    curl \
    wget \
    xxd \
    strings \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /sandbox
COPY run_analysis.sh /sandbox/run_analysis.sh
RUN chmod +x /sandbox/run_analysis.sh

CMD ["/bin/bash"]
