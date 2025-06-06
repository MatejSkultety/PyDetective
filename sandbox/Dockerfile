FROM ubuntu

WORKDIR /app

RUN apt-get update && \
    apt-get install -y curl python3 python3-pip clamav clamav-daemon clamav-freshclam && \
    apt-get clean && \
    freshclam

COPY executor.py /app/executor.py