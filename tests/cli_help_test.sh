#!/bin/bash
set -e
BIN=./alyncoin-cli

# No arguments -> help
$BIN > /tmp/noargs.txt
grep -q "Usage: alyncoin-cli" /tmp/noargs.txt

# --help
$BIN --help > /tmp/help.txt
grep -q "wallet new" /tmp/help.txt

# --version
$BIN --version > /tmp/version.txt
grep -q "alyncoin-cli" /tmp/version.txt

# send l1 missing params should fail
if $BIN send l1 > /tmp/send.txt 2>&1; then
  echo "send l1 unexpectedly succeeded" >&2
  exit 1
fi
grep -q "Usage: alyncoin-cli send" /tmp/send.txt

echo "CLI help tests passed"
