FROM debian:bullseye

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update && apt upgrade -y
RUN apt install -y apt-utils
RUN apt install -y libccid \
    libpcsclite-dev \
    git \
    autoconf \
    pkg-config \
    libtool \
    help2man \
    automake \
    gcc \
    make \
    build-essential \
    opensc \
    python3 \
    python3-pip \
    swig \
    cmake \
    libfuse-dev \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install pytest pycvc cryptography pyscard inputimeout
RUN git clone https://github.com/polhenarejos/python-fido2.git
WORKDIR /python-fido2
RUN git checkout development
RUN pip3 install .
WORKDIR /
RUN git clone https://github.com/frankmorgner/vsmartcard.git
WORKDIR /vsmartcard/virtualsmartcard
RUN autoreconf --verbose --install
RUN ./configure --sysconfdir=/etc
RUN make && make install
WORKDIR /
