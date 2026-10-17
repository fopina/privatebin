#!/usr/bin/env bash
set -euo pipefail

message="pbin weekly integration test $(date -u +%FT%TZ)"
paste_url="$(echo "$message" | pbin --expire 5min)"

if [[ ! "$paste_url" =~ ^https://privatebin\.net/\?[^#[:space:]]+#[1-9A-HJ-NP-Za-km-z]+$ ]]; then
	printf 'pbin did not return a valid PrivateBin link\n' >&2
	exit 1
fi

printf 'PrivateBin live upload succeeded; paste expires in 5 minutes:\n%s\n' "$paste_url"
