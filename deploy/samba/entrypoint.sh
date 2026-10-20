#!/bin/sh
# Sets the scanner account's SMB password from a secret file, then runs smbd.
# The password never appears in the environment, the image, or the process list.
set -eu

secret="${SCANNER_PASSWORD_FILE:-/run/secrets/scanner_password}"
if [ ! -r "$secret" ]; then
    echo "scanner password secret not found at $secret" >&2
    exit 1
fi

password="$(head -n 1 "$secret")"
if [ "${#password}" -lt 12 ]; then
    echo "scanner password must be at least 12 characters" >&2
    exit 1
fi

printf '%s\n%s\n' "$password" "$password" | smbpasswd -s -a scanner >/dev/null
unset password

exec smbd --foreground --no-process-group --debug-stdout
