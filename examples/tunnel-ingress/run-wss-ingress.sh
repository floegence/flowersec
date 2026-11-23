#!/bin/sh
set -eu

if [ "$#" -ne 2 ] || [ -z "$1" ] || [ -z "$2" ] || [ "$1" = "$2" ]; then
  echo 'usage: run-wss-ingress.sh LISTEN_HOST:PORT PAIRING_HOST:PORT' >&2
  exit 2
fi

activate=$(command -v systemd-socket-activate) || {
  echo 'systemd-socket-activate is required on the ingress host' >&2
  exit 1
}
for proxyd in /usr/lib/systemd/systemd-socket-proxyd /lib/systemd/systemd-socket-proxyd; do
  if [ -x "$proxyd" ]; then
    # Socket activation passes the already bound listener to the foreground
    # proxy. No inherited application credentials are needed at this hop.
    exec env -i PATH=/usr/bin:/bin "$activate" --listen="$1" -- "$proxyd" "$2"
  fi
done
echo 'systemd-socket-proxyd is required on the ingress host' >&2
exit 1
