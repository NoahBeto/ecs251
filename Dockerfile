FROM ubuntu:latest

ENV PORT=8000
EXPOSE 8000

RUN apt-get update && apt-get install -y \
    sudo \
    procps \
    strace \
    apache2-utils \
    bc \
    build-essential \
    cmake \
    curl \
    liburing-dev \
    python3 \
    python3-pip 

WORKDIR /src

# pip install --no-cache-dir matplotlib --break-system-packages