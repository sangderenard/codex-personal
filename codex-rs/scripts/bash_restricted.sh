#!/usr/bin/env bash
# Restricted shell wrapper: disallows `cd ..` to keep execution within current directory
if [[ " $* " =~ (^|[[:space:]])cd[[:space:]]+\.\.( |$) ]]; then
  echo "Error: 'cd ..' is not allowed." >&2
  exit 1
fi
"$@"
