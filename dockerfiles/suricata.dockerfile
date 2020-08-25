from ubuntu:20.04

RUN apt update && \
    apt-get install -y software-properties-common
RUN add-apt-repository -y ppa:oisf/suricata-stable && \
    apt-get update && \
    apt-get install -y suricata
RUN mkdir -p /var/lib/suricata/rules/

