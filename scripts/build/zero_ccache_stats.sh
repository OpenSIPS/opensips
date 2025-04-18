#!/bin/sh

set -e

. $(dirname $0)/build.conf.sub
. $(dirname $0)/dockerize.sub

ccache --max-size=100M
ccache --cleanup
ccache --zero-stats
