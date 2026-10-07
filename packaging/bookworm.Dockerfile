# Debian 12 builder for release packages: the .deb then needs only glibc 2.36.
# Pin Rust and Debian 12 userspace; update this digest through dependency review.
FROM rust:1.94.1-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55

RUN apt-get update \
    && apt-get install -y --no-install-recommends binutils \
    && apt-get clean

WORKDIR /workspace
