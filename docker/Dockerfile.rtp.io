# syntax=docker/dockerfile:1.7-labs

ARG BASE_IMAGE="sippylabs/rtpproxy:latest"
FROM --platform=$TARGETPLATFORM $BASE_IMAGE AS build
LABEL maintainer="Maksym Sobolyev <sobomax@sippysoft.com>"

USER root

# Set Environment Variables
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /src

ARG LLVM_VER=18
ARG LLVM_VER_OLD=16
ARG TARGETPLATFORM
ARG BUILD_OS=ubuntu:latest
RUN --mount=type=bind,source=scripts/build,target=scripts/build \
 --mount=type=cache,target=/var/cache/apt,sharing=locked \
 env `./scripts/build/get-arch-buildargs.rtp.io platformopts` \
 sh -x scripts/build/install_depends.sh && \
 eval `./scripts/build/get-arch-buildargs.rtp.io platformopts` && \
 apt-get install -y libsrtp2-dev ${LINKER}
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
 apt-get install -y gpp python-is-python3 python3-pip
RUN --mount=type=bind,source=dist/voiptests/requirements.txt,target=requirements.txt \
 --mount=type=cache,target=/root/.cache/pip,sharing=locked \
 python -m pip install --break-system-packages -U -r requirements.txt

COPY --exclude=.git --exclude=.github --exclude=docker --exclude=dist \
 . .

ARG KEEP_MODULES="dialog sipmsgops sl tm rr maxfwd rtp.io rtpproxy textops"
ARG SKIP_MODULES="usrloc event_routing clusterer rtp_relay"
RUN mkdir tmp && cd modules && mv ${KEEP_MODULES} ${SKIP_MODULES} ../tmp && \
 rm -rf * && cd ../tmp && mv ${KEEP_MODULES} ${SKIP_MODULES} ../modules && \
 cd .. && rmdir tmp
RUN EXCLUDE_MODULES_ADD="${SKIP_MODULES}" \
 env `./scripts/build/get-arch-buildargs.rtp.io platformopts` \
 sh -x scripts/build/do_build.sh
RUN env ONE_MODULE=rtp.io LDFLAGS="-flto -fuse-ld=lld" CFLAGS=-flto \
 env `./scripts/build/get-arch-buildargs.rtp.io platformopts` \
 sh -x scripts/build/do_build.sh
COPY --exclude=.git --exclude=.github dist/rtpproxy dist/rtpproxy
RUN eval `./scripts/build/get-arch-buildargs.rtp.io platformopts` && \
 cd dist/rtpproxy && CC="${COMPILER}" ./configure

COPY --exclude=.git --exclude=.github dist/voiptests dist/voiptests

ENV MM_TYPE=opensips
ENV MM_BRANCH=master
ENV MM_ROOT=../..
ENV RTPP_BRANCH=DOCKER
ENV RTPPC_TYPE=rtp.io
ENV RTPPROXY_DIST=../../dist/rtpproxy
WORKDIR dist/voiptests
ENTRYPOINT [ "sh", "-x", "./test_run.sh" ]
