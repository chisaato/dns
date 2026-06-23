# syntax=docker/dockerfile:1
# 从零构建 dnsdist 2.1.0-rc1，全特性开启（含 YAML/Rust + MMDB）
# 添加了 dq:removeEDNSOption(code) Lua 绑定
#
# 构建：
#   docker build -t dnsdist-custom:2.1.0-rc1 -f Dockerfile.custom-dnsdist .
#

# ============================================================
# Stage 1: 构建环境
# ============================================================
FROM powerdns/dnsdist-21:2.1.0-rc1 AS build-env
USER root

# 编译工具链 + 所有 dev 包
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    clang \
    curl \
    lld \
    meson \
    ninja-build \
    pkg-config \
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

# 安装 Rust（仅用于编译 yaml 的 libdnsdist_rust.a）
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y -q 2>/dev/null
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustc --version && cargo --version

# 官方镜像已有 libdnsdist-quiche.so 运行时库，
# 这里补上编译用的头文件，省去编译 quiche 的漫长过程
RUN wget -qO /usr/include/quiche.h \
    https://raw.githubusercontent.com/cloudflare/quiche/0.29.1/quiche/include/quiche.h

# ============================================================
# Stage 2: 下载 dnsdist 源码
# ============================================================
FROM build-env AS source-dl

WORKDIR /source
RUN wget -qO- https://github.com/PowerDNS/pdns/archive/refs/tags/dnsdist-2.1.0-rc1.tar.gz \
    | tar xz --strip-components=1

# ============================================================
# Stage 3: 编译 dnsdist（全特性，含 YAML）
# ============================================================
FROM build-env AS builder

COPY --from=source-dl /source /source

# quiche 的 pkg-config 文件（用外部文件替代 heredoc）
COPY dnsdist-build/quiche.pc \
    /usr/lib/x86_64-linux-gnu/pkgconfig/quiche.pc

# 打过补丁的 Lua 绑定
COPY dnsdist-build/dnsdist-lua-bindings-dnsquestion.cc \
    /source/pdns/dnsdistdist/dnsdist-lua-bindings-dnsquestion.cc
COPY dnsdist-build/dnsdist-lua-bindings-network.cc \
    /source/pdns/dnsdistdist/dnsdist-lua-bindings-network.cc

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
# Stage 4: 运行时
# ============================================================
FROM powerdns/dnsdist-21:2.1.0-rc1

# 打过补丁的 dnsdist 二进制
COPY --from=builder /build/usr/local/bin/dnsdist /usr/local/bin/dnsdist
