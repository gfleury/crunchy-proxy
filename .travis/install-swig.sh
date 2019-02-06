#!/bin/bash

set -e # exit on failure (same as -o errexit)

lsb_release -a
apt-get update && apt-get install -y \
    build-essential \
    libpcre3-dev \
    autoconf \
    automake \
    libtool \
    bison \
    git \
    libboost-dev \
	python3-dev 

wget https://github.com/swig/swig/archive/rel-3.0.12.tar.gz \
&& tar -zxf rel-3.0.12.tar.gz \
&& cd swig-rel-3.0.12 \
&& rm -f ../rel-3.0.12.tar.gz \
&& ./autogen.sh \
&& ./configure \
&& make \
&& make install
set +e # turn off exit on failure (same as +o errexit)
