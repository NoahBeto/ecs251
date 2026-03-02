FROM ubuntu:latest

RUN apt-get update && apt-get install -y build-essential cmake liburing-dev curl bc apache2-utils python3 python3-pip
WORKDIR /src