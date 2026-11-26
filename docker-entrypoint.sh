#!/bin/sh
# Agent shells run as the same user, so they could read secrets in /proc/1/environ. This hands the
# secrets to belphegor through a pipe, which is empty once read, and starts PID 1 without them.
set -eu
# shortcut: one line per secret, so a value cannot contain a newline; change the format if one must.
exec 3<<EOF
BELPHEGOR_PG_DSN=${BELPHEGOR_PG_DSN:-}
BELPHEGOR_ADMIN_PASSWORD=${BELPHEGOR_ADMIN_PASSWORD:-}
BELPHEGOR_SETUP_TOKEN=${BELPHEGOR_SETUP_TOKEN:-}
ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}
OPENAI_API_KEY=${OPENAI_API_KEY:-}
EOF
unset BELPHEGOR_PG_DSN BELPHEGOR_ADMIN_PASSWORD BELPHEGOR_SETUP_TOKEN ANTHROPIC_API_KEY OPENAI_API_KEY
export BELPHEGOR_SECRETS_FD=3
exec tini -- /app/belphegor "$@"
