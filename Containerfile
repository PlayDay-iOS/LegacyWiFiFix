FROM golang:bookworm AS ply-builder
RUN go install howett.net/plist/cmd/ply@latest

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV THEOS=/opt/theos

# 1. Install dependencies
#    1.1. Install Theos prerequisites
#    1.2. Pre-install Theos dependencies
#    1.3. Clean up apt cache to reduce image size
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        bash \
        curl \
        sudo \
        build-essential \
        fakeroot \
        git \
        libxml2 \
        perl \
        rsync \
        zip \
        libtinfo6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ply-builder /go/bin/ply /usr/local/bin/ply

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# 2. Non-root user (Theos installer refuses to run as root)
RUN useradd -m -s /bin/bash builder \
    && echo "builder ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \
    && mkdir -p $THEOS && chown builder:builder $THEOS

# 3. Install Theos (CI=1 skips interactive prompts)
USER builder
RUN CI=1 bash -c "$(curl -fsSL https://raw.githubusercontent.com/theos/theos/master/bin/install-theos)"

# 4. Remove auto-downloaded SDKs
RUN rm -rf $THEOS/sdks/*.sdk

# 5. Install iPhoneOS 12.4 SDK
RUN $THEOS/bin/install-sdk iPhoneOS12.4

# 6. Strip i386/x86_64 from top-level TBD archs so the linker doesn't
#    mistake them for simulator libs (theos/sdks#56, still open).
RUN find $THEOS/sdks/iPhoneOS12.4.sdk -name '*.tbd' -exec sed -i \
        -e '/^archs:/s/, x86_64//g' \
        -e '/^archs:/s/x86_64, //g' \
        -e '/^archs:/s/, i386//g' \
        -e '/^archs:/s/i386, //g' {} +

USER root

WORKDIR /build
CMD ["bash", "-c", "make clean package FINALPACKAGE=1"]
