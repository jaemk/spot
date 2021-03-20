#!/bin/bash

set -e

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
(cd server/ && migrant list)

./bin/server
