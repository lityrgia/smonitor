# Contributing

Small, focused pull requests are preferred. Explain the investigation use case and the expected capture overhead.

Before opening a pull request:

1. Run `cargo fmt --all -- --check`.
2. Run `cargo clippy --workspace --all-targets --locked -- -D warnings`.
3. Run `./build-windows.ps1 -Configuration Release` on Windows with the SDK and WDK installed.
4. Test capture in an isolated Windows x64 VM.
5. If the binary protocol changes, update both `shared/scall_protocol.h` and `app/src/protocol.rs`, increment `SCALL_PROTOCOL_VERSION`, and document the compatibility break.

Never include binaries, private symbols, memory dumps, generated exports, certificates, or machine-specific Visual Studio files in a commit.
