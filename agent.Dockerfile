# ARG OS_TAG=18.04
# FROM ubuntu:${OS_TAG} as builder

# ARG OS_TAG
# ARG BUILD_TYPE=release
# ARG DEBIAN_FRONTEND=noninteractive

# RUN apt-get -qq update && \
#     apt-get -y install pbuilder aptitude

# COPY ./bcc /root/bcc

# WORKDIR /root/bcc

# RUN /usr/lib/pbuilder/pbuilder-satisfydepends && \
#     ./scripts/build-deb.sh ${BUILD_TYPE}

# FROM ubuntu:${OS_TAG}

# COPY --from=builder /root/bcc/*.deb /root/bcc/

# RUN \
#   apt-get update -y && \
#   DEBIAN_FRONTEND=noninteractive apt-get install -y python python3 python3-pip binutils libelf1 kmod  && \
#   if [ ${OS_TAG} = "18.04" ];then \
#     apt-get -y install python-pip && \
#     pip install dnslib cachetools ; \
#   fi ; \
#   pip3 install dnslib cachetools  && \
#   dpkg -i /root/bcc/*.deb

# FROM ubuntu:20.04

# # install bcc build dependencies
# RUN apt install -y bison build-essential cmake flex git libedit-dev \
#   libllvm7 llvm-7-dev libclang-7-dev python zlib1g-dev libelf-dev libfl-dev python3-distutils


FROM ubuntu:bionic-20210325

ENV PATH /usr/share/bcc/tools:$PATH
RUN sed -i "s#deb http://deb.debian.org/debian buster main#deb http://deb.debian.org/debian buster main contrib non-free#g" /etc/apt/sources.list

RUN apt-get update && apt-get install -y \
    ca-certificates \
    clang \
    curl \
    gcc \
    git \
    g++ \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies for libbcc
# FROM: https://github.com/iovisor/bcc/blob/master/INSTALL.md#install-build-dependencies
RUN apt-get update && apt-get install -y \
    debhelper \
    cmake \
    libllvm3.9 \
    llvm-dev \
    libclang-dev \
    libelf-dev \
    bison \
    flex \
    libedit-dev \
    clang-format \
    python \
    python3-pyroute2 \
    luajit \
    libluajit-5.1-dev \
    arping \
    iperf \
    ethtool \
    devscripts \
    zlib1g-dev \
    libfl-dev \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

ENV BCC_VERSION v0.20.0

RUN git clone --depth 1 --branch "$BCC_VERSION" https://github.com/iovisor/bcc.git /usr/src/bcc \
# RUN git clone --depth 1 https://github.com/iovisor/bcc.git /usr/src/bcc \
	&& ( \
		cd /usr/src/bcc \
		&& mkdir build \
		&& cd build \
		&& cmake .. -DCMAKE_INSTALL_PREFIX=/usr \
		&& make \
		&& make install \
	) \
	&& rm -rf /usr/src/bcc


RUN apt-get update
RUN apt-get install -y wget linux-headers-5.13.0-30-generic

RUN wget -P /tmp https://go.dev/dl/go1.17.6.linux-amd64.tar.gz

RUN tar -C /usr/local -xzf /tmp/go1.17.6.linux-amd64.tar.gz
RUN rm /tmp/go1.17.6.linux-amd64.tar.gz

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"


WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY ./pkg ./pkg
RUN go build pkg/cmd/example/main.go
COPY ./rules ./rules

CMD ["./main", "-rule", "rules/example.rules"]