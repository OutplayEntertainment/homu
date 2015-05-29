#!/bin/bash
set -e

# Add homu as command if needed
if [[ "$1" == -* ]]; then
	set -- homu "$@"
fi

exec "$@"
