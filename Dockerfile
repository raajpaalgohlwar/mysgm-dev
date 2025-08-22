FROM ubuntu:22.04 AS build-opendht

RUN apt-get update && apt-get install -y \
        dialog apt-utils \
    && apt-get clean \
    && echo 'debconf debconf/frontend select noninteractive' | debconf-set-selections

RUN apt-get update && apt-get install -y \
        build-essential pkg-config cmake git wget meson \
        libtool autotools-dev autoconf \
        python3-pip python3-dev python3-setuptools python3-build python3-virtualenv cython3 \
        libncurses5-dev libreadline-dev nettle-dev libcppunit-dev \
        libgnutls28-dev libuv1-dev libjsoncpp-dev libargon2-dev \
        libssl-dev libfmt-dev libasio-dev libmsgpack-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

COPY . /usr/local/src

WORKDIR /usr/local/src/opendht/thirdparty/expected-lite
RUN mkdir -p /usr/local/include/nonstd \
    && cp include/nonstd/expected.hpp /usr/local/include/nonstd/expected.hpp

WORKDIR /usr/local/src/opendht/thirdparty/restinio/dev
RUN cmake . \
                -DCMAKE_INSTALL_PREFIX=/usr/local \
                -DRESTINIO_TEST=Off \
                -DRESTINIO_SAMPLE=Off \
                -DRESTINIO_BENCHMARK=Off \
                -DRESTINIO_WITH_SOBJECTIZER=Off \
                -DRESTINIO_DEP_STANDALONE_ASIO=system \
                -DRESTINIO_DEP_LLHTTP=system \
                -DRESTINIO_DEP_FMT=system \
                -DRESTINIO_DEP_EXPECTED_LITE=system \
    && make -j2 && make install

WORKDIR /usr/local/src/opendht/thirdparty/llhttp
RUN mkdir build && cd build \
    && cmake .. \
                -DCMAKE_INSTALL_PREFIX=/usr/local \
    && make && make install

WORKDIR /usr/local/src/opendht
RUN mkdir build && cd build \
	&& cmake .. \
                -DCMAKE_INSTALL_PREFIX=/usr/local \
				-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=On \
				-DOPENDHT_C=On \
				-DOPENDHT_PEER_DISCOVERY=On \
				-DOPENDHT_PYTHON=Off \
				-DOPENDHT_TOOLS=On \
				-DOPENDHT_PROXY_SERVER=On \
				-DOPENDHT_PROXY_CLIENT=On \
				-DOPENDHT_SYSTEMD=Off \
                -DOPENDHT_DOWNLOAD_DEPS=Off \
	&& make -j8 && make install

FROM rust:1.89 AS build-mysgm

COPY . /usr/local/src

WORKDIR /usr/local/src/mysgm
RUN cargo build --release

FROM ubuntu:22.04 AS final

COPY --from=build-mysgm /usr/local/src/mysgm/target/release/mysgm /usr/local/bin
COPY --from=build-opendht /usr/local/bin /usr/local/bin
COPY --from=build-opendht /usr/local/lib /usr/local/lib

RUN apt-get update && apt-get install -y \
        libargon2-1 \
        libjsoncpp25 \
        libfmt8 \
        libreadline8 \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/*