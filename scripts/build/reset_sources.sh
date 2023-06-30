#!/bin/sh

RELEASE="$(lsb_release -cs)"
URL="http://archive.ubuntu.com/ubuntu"

echo "deb $URL $RELEASE main universe
deb $URL $RELEASE-updates main universe
deb $URL $RELEASE-security main universe" | sudo tee /etc/apt/sources.list > /dev/null

sudo rm -rf /etc/apt/sources.list.d
