#!/bin/sh
set -eu

case "${FLOWERSEC_CLIENT_NETNS:-}" in
  ""|*[!A-Za-z0-9_.-]*|.*|-*)
    echo "FLOWERSEC_CLIENT_NETNS is not a safe namespace name" >&2
    exit 64
    ;;
esac

case "${FLOWERSEC_CHROMIUM_EXECUTABLE:-}" in
  /*) ;;
  *)
    echo "FLOWERSEC_CHROMIUM_EXECUTABLE must be absolute" >&2
    exit 64
    ;;
esac

if [ ! -x "$FLOWERSEC_CHROMIUM_EXECUTABLE" ]; then
  echo "FLOWERSEC_CHROMIUM_EXECUTABLE is not executable" >&2
  exit 66
fi

exec ip netns exec "$FLOWERSEC_CLIENT_NETNS" "$FLOWERSEC_CHROMIUM_EXECUTABLE" "$@"
