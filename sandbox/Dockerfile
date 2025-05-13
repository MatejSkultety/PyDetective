FROM ubuntu

WORKDIR /app

RUN apt-get update && \
    apt-get install -y python3 python3-pip && \
    apt-get install -y clamav clamav-daemon && \
    apt-get install -y clamav-daemon && \
    apt-get install -y clamav-freshclam && \
    apt-get install -y chkrootkit && \
    apt-get clean

COPY executor.py /app/executor.py