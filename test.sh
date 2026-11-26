#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
mkdir -p .build
out=$(mktemp -d "$PWD/.build/test.XXXXXX")
export PYTHONDONTWRITEBYTECODE=1 CLANG_MODULE_CACHE_PATH="$out/cache"
for name in helper verify; do
    clang -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined "host_link/test_$name.c" host_link/admin_socket.c -o "$out/$name"
    "$out/$name"
done
python3 guest/test_station_guest.py
python3 test_station.py
