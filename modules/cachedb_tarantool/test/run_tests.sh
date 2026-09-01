#!/bin/sh
set -e

cd "$(dirname "$0")"
make clean
make test
