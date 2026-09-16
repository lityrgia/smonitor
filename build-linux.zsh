#!/usr/bin/env zsh

setopt errexit nounset pipefail

config=${1:-Debug}
if [[ $config != Debug && $config != Release ]]; then
    print -u2 "usage: ${0:t} [Debug|Release]"
    exit 2
fi

root=${0:A:h}
profile=${config:l}
cargo_args=(xwin build --target x86_64-pc-windows-msvc)
if [[ $config == Release ]]; then
    cargo_args+=(--release)
fi

"$root/driver/build-driver.zsh" "$config"
cargo "${cargo_args[@]}" --manifest-path "$root/Cargo.toml"

mkdir -p "$root/dist"
cp "$root/driver/outputs/x64/$config/swatcher.sys" "$root/dist/"
cp "$root/target/x86_64-pc-windows-msvc/$profile/smonitor.exe" "$root/dist/"
if [[ ! -e "$root/dist/filters.example.json" ]]; then
    cp "$root/filters.example.json" "$root/dist/"
fi
if [[ ! -e "$root/dist/filters.json" ]]; then
    cp "$root/filters.example.json" "$root/dist/filters.json"
fi

print "built: $root/dist/swatcher.sys"
print "built: $root/dist/smonitor.exe"
print "example: $root/dist/filters.example.json"
