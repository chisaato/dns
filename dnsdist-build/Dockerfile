# syntax=docker/dockerfile:1
# 从 Debian trixie 构建 dnsdist 2.1.0-rc1，全特性开启（含 YAML/Rust + quiche）

# ============================================================
# Stage 1: 构建环境
# ============================================================
FROM debian:trixie AS build-env

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    clang \
    curl \
    file \
    lld \
    lua-filesystem \
    ninja-build \
    patch \
    pkg-config \
    python3-pip \
    python3-yaml \
    ragel \
    wget \
    libboost-dev \
    libboost-container-dev \
    libbpf-dev \
    libcap-dev \
    libcdb-dev \
    libedit-dev \
    libfstrm-dev \
    libgnutls28-dev \
    liblmdb-dev \
    libluajit-5.1-dev \
    libnghttp2-dev \
    libre2-dev \
    libsnmp-dev \
    libsodium-dev \
    libssl-dev \
    libxdp-dev \
    && apt-get clean

RUN pip3 install --break-system-packages meson

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y -q 2>/dev/null
ENV PATH="/root/.cargo/bin:${PATH}"

RUN wget -qO /usr/include/quiche.h \
    https://raw.githubusercontent.com/cloudflare/quiche/0.29.1/quiche/include/quiche.h

# ============================================================
# Stage 1.5: 从官方镜像提取 quiche 运行时库
# ============================================================
FROM powerdns/dnsdist-21:2.1.0-rc1 AS quiche-lib
RUN cp /usr/lib/x86_64-linux-gnu/libdnsdist-quiche.so* /tmp/

# ============================================================
# Stage 2: 下载源码
# ============================================================
FROM build-env AS source-dl

WORKDIR /source
RUN wget -qO- https://github.com/PowerDNS/pdns/archive/refs/tags/dnsdist-2.1.0-rc1.tar.gz \
    | tar xz --strip-components=1

# ============================================================
# Stage 3: 打补丁 + 编译
# ============================================================
FROM build-env AS builder

COPY --from=source-dl /source /source
COPY --from=quiche-lib /tmp/libdnsdist-quiche.so* /usr/lib/x86_64-linux-gnu/

COPY dnsdist-build/quiche.pc \
    /usr/lib/x86_64-linux-gnu/pkgconfig/quiche.pc

COPY dnsdist-build/dnsdist-lua-bindings-dnsquestion.cc \
    /source/pdns/dnsdistdist/dnsdist-lua-bindings-dnsquestion.cc
COPY dnsdist-build/dnsdist-lua-bindings-network.cc \
    /source/pdns/dnsdistdist/dnsdist-lua-bindings-network.cc

COPY dnsdist-build/dnsdist-cache.hh \
    /source/pdns/dnsdistdist/dnsdist-cache.hh
COPY dnsdist-build/dnsdist-cache.cc \
    /source/pdns/dnsdistdist/dnsdist-cache.cc
COPY dnsdist-build/dnsdist-lua-bindings-packetcache.cc \
    /source/pdns/dnsdistdist/dnsdist-lua-bindings-packetcache.cc
COPY dnsdist-build/dnsdist-configuration.hh \
    /source/pdns/dnsdistdist/dnsdist-configuration.hh

COPY dnsdist-build/dnsdist-persistent-cache.patch /tmp/
RUN patch -p0 -d /source < /tmp/dnsdist-persistent-cache.patch && rm /tmp/dnsdist-persistent-cache.patch

WORKDIR /source/pdns/dnsdistdist
RUN touch dnsdist.1

RUN mkdir /build && \
    BUILDDIR=$(mktemp -d) && \
    IS_RELEASE=YES \
    BUILDER_VERSION=2.1.0-rc1 \
    LDFLAGS="-fuse-ld=lld -Wl,--build-id=sha1" \
    CC=clang CXX=clang++ \
    meson setup ${BUILDDIR} \
    --sysconfdir=/etc/dnsdist \
    -Dlua=luajit \
    -Db_lto=true \
    -Db_lto_mode=thin \
    -Db_pie=true \
    -Dcdb=enabled \
    -Ddns-over-https=enabled \
    -Ddns-over-quic=enabled \
    -Ddns-over-http3=enabled \
    -Ddns-over-tls=enabled \
    -Ddnscrypt=enabled \
    -Ddnstap=enabled \
    -Dlmdb=enabled \
    -Dyaml=enabled \
    -Debpf=enabled \
    -Dtls-gnutls=enabled \
    -Dsnmp=enabled \
    -Dlibcap=enabled \
    -Dlibsodium=enabled \
    -Dquiche=enabled \
    -Dre2=enabled \
    -Dsystemd-service=disabled \
    -Dxsk=enabled && \
    meson compile -C ${BUILDDIR} && \
    meson install -C ${BUILDDIR} --destdir /build && \
    strip /build/usr/local/bin/*

# ============================================================
# Stage 4: 运行时（精简的 trixie）
# ============================================================
FROM debian:trixie-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    libbpf1 \
    libcap2 \
    libcdb1 \
    libedit2 \
    libfstrm0 \
    libgnutls30t64 \
    liblmdb0 \
    libluajit-5.1-2 \
    libnghttp2-14 \
    libre2-11 \
    libsnmp40t64 \
    libsodium23 \
    libssl3t64 \
    libxdp1 \
    tini \
    && apt-get clean

COPY --from=builder /build/usr/local/bin/dnsdist /usr/local/bin/dnsdist
COPY --from=quiche-lib /tmp/libdnsdist-quiche.so* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/lua/5.1/lfs.so /usr/lib/x86_64-linux-gnu/lua/5.1/
RUN ldconfig

ENTRYPOINT ["dnsdist"]
CMD ["--supervised", "-C", "/etc/dnsdist/dnsdist.conf"]
