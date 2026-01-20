#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install|post-upgrade)
    echo -e "\nODS2CASCADE VERSION:"
    ods2cascade --version

    echo -e "\nODS2CASCADE MAN PAGE (first 20 lines only):"
    man -P cat ods2cascade | head -n 20 || true
    ;;
esac
