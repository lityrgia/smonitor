## Summary

Describe the change and why it is needed.

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `./build-windows.ps1 -Configuration Release`
- [ ] Capture tested in an isolated Windows x64 VM
- [ ] Protocol structs were updated on both sides, if their ABI changed

## Capture impact

Describe any change to syscall coverage, filtering, queue pressure, argument reads, or supported Windows builds.
