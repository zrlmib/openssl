From ubuntu:18.04

MAINTAINER MIB (mib@zurich.ibm.com)

ENV DEBIAN_FRONTEND noninteractive

# Get a fresh system:
RUN apt-get update -y
RUN apt-get -y upgrade

# Why didn't the first update pick up all dependencies?!?
RUN apt-get update -y

# Lots of stuff to build the many components:
RUN apt-get install -y autoconf automake gcc libtool libssl-dev make unzip xsltproc git vim psmisc python3 python3-pip

# For oqs_testing:
RUN pip3 install nose rednose

# Main build script
ADD build-qsc-openssl.sh /root/sh/build-qsc-openssl.sh

# Some tests
ADD oqs-speedtest /bin/oqs-speedtest
ADD oqs-sslserver /bin/oqs-sslserver
ADD oqs-sslclient /bin/oqs-sslclient

# Build liboqs and openssl (1.1.1) into the image
RUN /root/sh/build-qsc-openssl.sh /usr/local/openssl

WORKDIR /root

# start with docker -it <name> bash to log in and develop
# build environment is in /root/build: git pull in both repos to be up-to-date
CMD ["openssl", "version"]
