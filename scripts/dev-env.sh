#!/bin/sh
# Writes a .env with freshly generated local-only credentials for docker compose.
set -eu
if [ -e .env ]; then
  echo ".env already exists; leaving it alone" >&2
  exit 0
fi
umask 077
cat > .env <<ENV
POSTGRES_PASSWORD=$(openssl rand -hex 16)
GARAGE_RPC_SECRET=$(openssl rand -hex 32)
GARAGE_ADMIN_TOKEN=$(openssl rand -hex 32)
S3_ACCESS_KEY_ID=GK$(openssl rand -hex 12)
S3_SECRET_ACCESS_KEY=$(openssl rand -hex 32)
ENV
echo "wrote .env"
