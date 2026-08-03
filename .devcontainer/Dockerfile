# Dev environment from a plain Ubuntu base: everything installed
# explicitly, the same way you would on a real Linux machine.
#
# Exception: p4c + BMv2 come prebuilt from qobilidop/p4lang-builds
# (personal multi-arch images with immutable version tags; recipes in
# that repo). No packages exist for Ubuntu 24.04 and a source build
# costs ~50 minutes per cold start.
ARG P4C_VERSION=1.2.5.15
ARG BMV2_VERSION=1.15.4
FROM ghcr.io/qobilidop/p4lang-builds/p4c:${P4C_VERSION}-noble@sha256:794edb1682e286792fbf7b1ca5da2ed7be52ddbeab3659a3bbfb4e1906684e48 AS p4c
FROM ghcr.io/qobilidop/p4lang-builds/bmv2:${BMV2_VERSION}-noble@sha256:3c70f7516440e36a217a7685364a1d1ffb766d0965ab3fbd549f8bbaf7c3cc9d AS bmv2

FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

ENV DEBIAN_FRONTEND=noninteractive

# Freeze apt metadata as well as the base image. Updating this timestamp is an
# explicit dependency-upgrade change, never an invisible monthly rebuild.
ARG UBUNTU_SNAPSHOT=20260802T000000Z
RUN sed -E -i \
      "s#https?://(archive.ubuntu.com/ubuntu|security.ubuntu.com/ubuntu|ports.ubuntu.com/ubuntu-ports)/?#https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}/#g" \
      /etc/apt/sources.list.d/ubuntu.sources \
 && echo 'Acquire::Check-Valid-Until "false";' >/etc/apt/apt.conf.d/99snapshot \
 && echo 'Acquire::https::Verify-Peer "false";' >/etc/apt/apt.conf.d/00bootstrap-ca

# The minimal Ubuntu base has no CA bundle. Bootstrap the single frozen apt
# transaction with TLS peer verification disabled; apt still verifies the
# snapshot's signed Release metadata and every package hash. All later network
# downloads use the installed CA bundle and normal TLS verification.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl build-essential git \
      protobuf-compiler tshark graphviz \
      libz3-dev libclang-dev clang llvm libbpf-dev \
      # DPDK for the dpdk_ptype oracle (rte_net_get_ptype); noble ships
      # 23.11.x — the version tag in the committed goldens. Costs ~image
      # size only: the dev package pulls every librte PMD.
      libdpdk-dev pkg-config \
      python3 python3-pip python3-venv shellcheck clang-format \
      libboost-iostreams-dev libboost-graph-dev libgc-dev libfl-dev \
      libgmp-dev libpcap-dev libjudy-dev libevent-dev libssl-dev \
      libxxhash-dev libjsoncpp-dev libthrift-dev \
      libboost-program-options-dev libboost-system-dev \
      libboost-filesystem-dev libboost-thread-dev \
 && rm /etc/apt/apt.conf.d/00bootstrap-ca \
 && rm -rf /var/lib/apt/lists/*

# buf CLI (pinned)
ARG BUF_VERSION=1.47.2
RUN case "$(uname -m)" in \
      x86_64)  sha=3a0c4da8d46eea8136affa63db202c76a44f8112384160b73c3fffb1cf14b5d8 ;; \
      aarch64) sha=47ddd7ac0bb2a29f8c92aa420dd113bed3b6857190976402eec93ab9847270b4 ;; \
      *) echo "unsupported architecture" >&2; exit 1 ;; \
    esac \
 && download="$(mktemp)" \
 && curl -fsSL "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-$(uname -s)-$(uname -m)" -o "$download" \
 && echo "$sha  $download" | sha256sum --check --strict \
 && install -m 0755 "$download" /usr/local/bin/buf

# p4c + BMv2, grafted from the prebuilt images pinned above (both are
# noble-based, so /usr/local grafts cleanly). The apt line installs the
# union of the runtime deps listed in each image's final stage (-dev
# packages for simplicity: they pull the runtime libs; the headers cost
# size, not correctness). cpp — p4c's runtime preprocessor — is already
# present via build-essential; python3 serves p4c's helper scripts.
COPY --from=p4c /usr/local /usr/local
COPY --from=bmv2 /usr/local /usr/local
RUN ldconfig \
 && p4test --version \
 && p4c-bm2-ss --version \
 && simple_switch --help >/dev/null 2>&1

# Python authoring-surface tooling. Direct and transitive dependencies are
# version- and hash-locked in the build context.
COPY requirements.txt /tmp/pakeles-requirements.txt
RUN python3 -m pip install --break-system-packages --no-cache-dir \
      --require-hashes -r /tmp/pakeles-requirements.txt

# Rust via rustup, default profile (includes rustfmt + clippy).
# System-wide homes so dev.sh cache volumes can mount over them.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    PROTOC=/usr/bin/protoc \
    CARGO_TARGET_DIR=/target
ARG RUST_VERSION=1.97.1
RUN case "$(uname -m)" in \
      x86_64)  target=x86_64-unknown-linux-gnu; sha=4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10 ;; \
      aarch64) target=aarch64-unknown-linux-gnu; sha=9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792 ;; \
      *) echo "unsupported architecture" >&2; exit 1 ;; \
    esac \
 && download_dir="$(mktemp -d)" \
 && download="$download_dir/rustup-init" \
 && curl -fsSL "https://static.rust-lang.org/rustup/dist/${target}/rustup-init" -o "$download" \
 && echo "$sha  $download" | sha256sum --check --strict \
 && chmod +x "$download" \
 && "$download" -y --profile default --default-toolchain "$RUST_VERSION" --no-modify-path \
 && rm -rf "$download_dir"

# Shell/C/workflow linters for scripts/lint.sh: shellcheck and
# clang-format from apt (clang-format shares the LLVM libs the bpf
# backend already pulls in), actionlint pinned the same way as buf.
# Last layer on purpose: bumping a linter pin must not invalidate the
# Rust layer above.
ARG ACTIONLINT_VERSION=1.7.7
RUN case "$(dpkg --print-architecture)" in \
      amd64) sha=023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757 ;; \
      arm64) sha=401942f9c24ed71e4fe71b76c7d638f66d8633575c4016efd2977ce7c28317d0 ;; \
      *) echo "unsupported architecture" >&2; exit 1 ;; \
    esac \
 && download="$(mktemp)" \
 && curl -fsSL "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_$(dpkg --print-architecture).tar.gz" -o "$download" \
 && echo "$sha  $download" | sha256sum --check --strict \
 && tar -xzf "$download" -C /usr/local/bin actionlint
