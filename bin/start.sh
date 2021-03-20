#!/bin/bash

set -e

BUILD=false

function die_usage {
  echo "Usage: $(basename $0) [-bh]"
  echo ""
  echo "Options:"
  echo "  -h           Show this beautiful message"
  echo "  -b           Build the artifacts if they're missing"
  echo ""
  exit 1
}

while getopts "bh" opt; do
  case $opt in
    b) BUILD=true ;;
    h) die_usage ;;
    \? ) die_usage
      ;;
  esac
done

if $BUILD; then
  (cd server; cargo build)
  cp server/target/debug/server bin/server
  echo "built the server"
fi

if [[ ! -f bin/server ]]; then
  echo "missing bin/server executable"
  exit 1
fi

if [[ -f /etc/secrets/.env ]]; then
  echo "copying /etc/secrets/.env to .env"
  cp /etc/secrets/.env .env
  cp /etc/secrets/.env server/.env
fi

(cd server/ && migrant list)
(cd server/ && migrant apply -a || true)

./bin/server
