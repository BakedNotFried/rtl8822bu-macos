#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
mkdir -p .build
# Reuse a complete build of these sources on this OS. Partial builds are ignored.
fingerprint=$(
    { sw_vers -buildVersion; shasum -a 256 build-station.sh station.py credential.m psk.m probe.c \
        host_link/*.c host_link/*.h guest/*.py guest/*.pub guest/*.json guest/station-guest guest/init guest/LICENCE.rtlwifi_firmware.txt vm/prepare.py vm/*.json; } |
        shasum -a 256 | cut -d ' ' -f 1
)
for previous in "$PWD"/.build/station.*; do
    if [ -f "$previous/complete" ] && [ "$(cat "$previous/complete")" = "$fingerprint" ] &&
       [ -x "$previous/station" ] && [ -x "$(tail -n 1 "$previous/qemu.path")" ] &&
       [ -s "$previous/guest/Image" ] && [ -s "$previous/guest/initramfs.gz" ]; then
        printf '%s\n' "$previous/station"
        exit 0
    fi
done
out=$(mktemp -d "$PWD/.build/station.XXXXXX")
export CLANG_MODULE_CACHE_PATH="$out/cache"
clang -arch arm64 -Wall -Wextra -Werror probe.c -framework IOKit -framework CoreFoundation -o "$out/usb-probe"
clang -arch arm64 -std=c11 -Wall -Wextra -Werror host_link/helper.c host_link/admin_socket.c -o "$out/host-link-helper"
clang -arch arm64 -std=c11 -Wall -Wextra -Werror host_link/verify.c -o "$out/host-link-verify"
clang -arch arm64 -Wall -Wextra -Werror -fobjc-arc credential.m psk.m -framework AppKit -framework Foundation -framework CoreWLAN -framework Security -o "$out/psk"
python3 guest/build.py "$out/guest" >&2
python3 vm/prepare.py "$out/vm" > "$out/qemu.path"
cp station.py "$out/station"
chmod 700 "$out/station"
printf '%s\n' "$fingerprint" > "$out/complete"
printf '%s\n' "$out/station"
