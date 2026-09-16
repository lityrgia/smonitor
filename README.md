# Syscall Monitor

## Introduction

Syscall Monitor is a lightweight native system-call monitor for Windows x64. It consists of the
`swatcher.sys` kernel driver and an `egui`-based Rust interface named `smonitor.exe`.

Inspired by [hzqst/Syscall-Monitor](https://github.com/hzqst/Syscall-Monitor) but uses a different capture
method.

> [!WARNING]
> The driver relies on undocumented Windows kernel internals and may cause a BSOD on an unsupported
> build. Use it only in an isolated test VM with a snapshot.

## Features

- Live syscall view with process names, icons, PID/TID, and entry arguments
- Kernel-side filtering by process name, PID, operation, and category
- Include/exclude operation rules and GUI search filters
- JSON operation filters with first-four-argument conditions
- Bounded kernel queues and configurable GUI memory usage
- CSV, JSONL, and TXT export
- Light and dark themes

## Screenshots

![Syscall capture](images/captures.png)

![Capture statistics](images/statistics.png)

## How it works

The driver builds its syscall table from the standard x64 `Nt*` stubs exported by the local
`ntdll.dll`. It records user-mode entries into the main NT service table and sends them to the GUI
through bounded queues. Process and operation filters are applied in the driver before an event is
queued.

Common file, registry, process, thread, memory, token, IPC, and synchronization calls have typed
decoders. They can show object paths, access masks, sizes, protection flags, target PIDs/process
names, and other input data. `NtOpenKeyEx` shows the registry key path, requested access, and open
options. Other calls show their first four raw arguments. The monitor does not replace syscall
targets or collect return values.

Experimental Win32k capture is available for `NtUser*`, `NtGdi*`, and related calls exported by
`win32u.dll`. Enable the **User** or **Graphics** category together with a process filter; both are
disabled by default because GUI applications generate a very high event rate.

## Build

Windows requirements: Visual Studio 2022, Windows SDK, WDK, stable Rust, and the
`x86_64-pc-windows-msvc` target.

```powershell
rustup target add x86_64-pc-windows-msvc
.\build-windows.ps1 -Configuration Release
```

The Linux cross-build expects the MSVC/SDK/WDK tree configured by `driver/build-driver.zsh` and
`cargo-xwin`:

```bash
./build-linux.zsh Release
```

Both scripts place the unsigned files in `dist/`:

```text
smonitor.exe
swatcher.sys
```

## Usage

Release builds use kdmapper to load the driver. Run `start.bat` as
Administrator.

### JSON filters

Open the **...** operation menu, enter a JSON file name, and press **Load**. Relative paths are
resolved next to `smonitor.exe`. Builds create a starter `filters.json` without overwriting an
existing file; the original template is also included as `filters.example.json`:

```json
{
  "include": [],
  "exclude": ["NtDeviceIoControlFile"],
  "rules": [
    {
      "op": "NtOpenProcess",
      "skip": { "arg1": "0x100" }
    },
    {
      "op": "NtWriteVirtualMemory",
      "only": { "arg1": "0x40", "arg4": 4096 }
    }
  ]
}
```

`skip` drops the call when all listed arguments match. `only` does the opposite: for that operation,
only calls matching at least one `only` rule are retained. Conditions inside one rule use AND;
multiple rules use OR. Use `arg1` through `arg4`. Values accept JSON unsigned numbers or strings
such as `"0x100"`. Up to 128 rules are applied in the driver before events enter the queue. The old
verbose syntax remains readable for compatibility.

## Platform

Windows 10/11 x64. Compatibility must be checked for each Windows build because the capture method
depends on internal kernel implementation details. WOW64 is not supported, and Win32k capture is
experimental.

## License

[MIT](LICENSE)
