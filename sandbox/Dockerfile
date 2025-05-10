FROM ubuntu

WORKDIR /app

# Install Python and pip
RUN apt-get update && \
    apt-get install -y python3 python3-pip && \
    apt-get install -y clamav clamav-daemon clamav-freshclam && \
    apt-get install -y chkrootkit && \
    apt-get clean
