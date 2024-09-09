#!/bin/sh

set -e

. $(dirname $0)/dockerize.sub

. $(dirname $0)/build.conf.sub

ccache --show-stats
