use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::thread;
use std::time::Duration;

#[cfg(not(windows))]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use std::time::Instant;

use crate::protocol::{DriverConfig, DriverStats, RawEvent};

#[cfg(not(windows))]
use crate::protocol::ALL_CATEGORIES;

#[cfg(windows)]
use crate::protocol::{MAX_SYSCALLS, RawDetail, RawSyscallInfo};

pub enum SourceCommand {
    Configure(Box<DriverConfig>),
    Stop,
}

pub enum SourceMessage {
    Status(String),
    Events(Vec<RawEvent>),
    Details(Vec<(u64, u16, String)>),
    SyscallTable(Vec<(u16, u16, String)>),
    Stats(DriverStats),
}

pub struct SourceHandle {
    pub commands: Sender<SourceCommand>,
    pub messages: Receiver<SourceMessage>,
}

impl SourceHandle {
    pub fn spawn() -> Self {
        let (command_tx, command_rx) = channel();
        let (message_tx, message_rx) = channel();
        thread::Builder::new()
            .name("scall-collector".into())
            .spawn(move || run_source(command_rx, message_tx))
            .expect("failed to spawn collector");
        Self {
            commands: command_tx,
            messages: message_rx,
        }
    }
}

#[cfg(windows)]
fn run_source(commands: Receiver<SourceCommand>, messages: Sender<SourceMessage>) {
    windows_source::run(commands, messages);
}

#[cfg(not(windows))]
fn run_source(commands: Receiver<SourceCommand>, messages: Sender<SourceMessage>) {
    let _ = messages.send(SourceMessage::Status(
        "Demo source (the driver transport is enabled in Windows builds)".into(),
    ));
    let table = demo_table();
    let _ = messages.send(SourceMessage::SyscallTable(table.clone()));
    let mut config = DriverConfig {
        version: crate::protocol::PROTOCOL_VERSION,
        category_mask: ALL_CATEGORIES,
        capture_enabled: 1,
        excluded_pid: std::process::id(),
        target_pid_count: 1,
        target_pids: {
            let mut pids = [0; crate::protocol::MAX_TARGET_PIDS];
            pids[0] = 4242;
            pids
        },
        target_name_count: 0,
        target_names: [[0; crate::protocol::PROCESS_NAME_BYTES]; crate::protocol::MAX_TARGET_NAMES],
        operation_mask: [u32::MAX; crate::protocol::OPERATION_MASK_WORDS],
    };
    let mut sequence = 0_u64;
    let mut captured = 0_u64;
    loop {
        loop {
            match commands.try_recv() {
                Ok(SourceCommand::Configure(next)) => config = *next,
                Ok(SourceCommand::Stop) | Err(TryRecvError::Disconnected) => return,
                Err(TryRecvError::Empty) => break,
            }
        }
        if config.capture_enabled != 0 {
            let mut batch = Vec::with_capacity(350);
            let local_second = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                % 86_400;
            for n in 0..350_u32 {
                let (id, category, _) = &table[(sequence as usize) % table.len()];
                sequence = sequence.wrapping_add(1);
                if config.category_mask & (1 << *category) == 0 {
                    continue;
                }
                let syscall_id = usize::from(*id);
                if config.operation_mask[syscall_id / 32] & (1 << (syscall_id % 32)) == 0 {
                    continue;
                }
                batch.push(RawEvent {
                    qpc: local_second,
                    pid: if config.target_pid_count == 0 {
                        4242 + n % 3
                    } else {
                        config.target_pids[(n as usize) % config.target_pid_count as usize]
                    },
                    tid: 5000 + n % 12,
                    syscall_id: *id,
                    category: *category,
                    flags: crate::protocol::EVENT_FLAG_ARGUMENTS_VALID,
                    sequence,
                    arguments: [
                        0x1000 + u64::from(n),
                        0x2000 + u64::from(n),
                        0x3000 + u64::from(n),
                        0x4000 + u64::from(n),
                    ],
                    process_name: {
                        let mut name = [0; crate::protocol::PROCESS_NAME_BYTES];
                        name[..8].copy_from_slice(b"demo.exe");
                        name
                    },
                });
            }
            captured += batch.len() as u64;
            let _ = messages.send(SourceMessage::Events(batch));
            if sequence % 1400 < 350 {
                let _ = messages.send(SourceMessage::Details(vec![(
                    sequence,
                    0,
                    "Path=\\Device\\HarddiskVolume3\\demo.txt Access=0x120089".into(),
                )]));
            }
            let _ = messages.send(SourceMessage::Stats(DriverStats {
                version: crate::protocol::PROTOCOL_VERSION,
                ring_capacity: 65_536,
                captured,
                delivered: captured,
                ..Default::default()
            }));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(not(windows))]
fn demo_table() -> Vec<(u16, u16, String)> {
    [
        (0x55, 0, "NtCreateFile"),
        (0x06, 0, "NtReadFile"),
        (0x08, 0, "NtWriteFile"),
        (0x18, 1, "NtOpenKey"),
        (0x17, 1, "NtQueryValueKey"),
        (0x26, 2, "NtOpenProcess"),
        (0xc1, 3, "NtCreateThreadEx"),
        (0x50, 4, "NtProtectVirtualMemory"),
        (0x21, 5, "NtOpenProcessToken"),
        (0x9f, 6, "NtAlpcSendWaitReceivePort"),
        (0x04, 7, "NtWaitForSingleObject"),
        (0x36, 8, "NtQuerySystemInformation"),
        (0x0f, 9, "NtClose"),
    ]
    .into_iter()
    .map(|(id, category, name)| (id, category, name.to_owned()))
    .collect()
}

#[cfg(windows)]
mod windows_source {
    use super::*;
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_READ, GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE, SYSTEMTIME,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Performance::QueryPerformanceCounter;
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;

    const FILE_DEVICE_UNKNOWN: u32 = 0x22;
    const FILE_READ_ACCESS: u32 = 1;
    const FILE_WRITE_ACCESS: u32 = 2;
    const METHOD_BUFFERED: u32 = 0;
    const METHOD_OUT_DIRECT: u32 = 2;
    const fn ctl_code(function: u32, method: u32, access: u32) -> u32 {
        (FILE_DEVICE_UNKNOWN << 16) | (access << 14) | (function << 2) | method
    }
    const IOCTL_SET_CONFIG: u32 = ctl_code(0x800, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    const IOCTL_READ_EVENTS: u32 = ctl_code(0x801, METHOD_OUT_DIRECT, FILE_READ_ACCESS);
    const IOCTL_GET_STATS: u32 = ctl_code(0x802, METHOD_BUFFERED, FILE_READ_ACCESS);
    const IOCTL_GET_TABLE: u32 = ctl_code(0x803, METHOD_OUT_DIRECT, FILE_READ_ACCESS);
    const IOCTL_READ_DETAILS: u32 = ctl_code(0x804, METHOD_OUT_DIRECT, FILE_READ_ACCESS);

    pub fn run(commands: Receiver<SourceCommand>, messages: Sender<SourceMessage>) {
        let path: Vec<u16> = "\\\\.\\ScallMonitor\0".encode_utf16().collect();
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            let _ = messages.send(SourceMessage::Status(
                "Cannot open \\.\\ScallMonitor; load the driver and restart the app".into(),
            ));
            return;
        }
        let Some(initial_stats) = query_stats(handle) else {
            let _ = messages.send(SourceMessage::Status(
                "Driver protocol check failed; reload the driver".into(),
            ));
            unsafe { CloseHandle(handle) };
            return;
        };
        if initial_stats.version != crate::protocol::PROTOCOL_VERSION {
            let _ = messages.send(SourceMessage::Status(format!(
                "Driver protocol v{} is loaded, GUI needs v{}; reboot and load the new .sys",
                initial_stats.version,
                crate::protocol::PROTOCOL_VERSION
            )));
            unsafe { CloseHandle(handle) };
            return;
        }
        let _ = messages.send(SourceMessage::Stats(initial_stats));
        let _ = messages.send(SourceMessage::Status("Driver connected".into()));
        send_table(handle, &messages);
        let mut event_buffer = vec![RawEvent::default(); 4096];
        let mut detail_buffer = vec![unsafe { zeroed::<RawDetail>() }; 8192];
        let mut last_stats = Instant::now();
        loop {
            loop {
                match commands.try_recv() {
                    Ok(SourceCommand::Configure(config)) => {
                        let mut returned = 0;
                        let ok = unsafe {
                            DeviceIoControl(
                                handle,
                                IOCTL_SET_CONFIG,
                                config.as_ref() as *const _ as *const c_void,
                                size_of::<DriverConfig>() as u32,
                                null_mut(),
                                0,
                                &mut returned,
                                null_mut(),
                            )
                        };
                        if ok == 0 {
                            let error = unsafe { GetLastError() };
                            let _ = messages.send(SourceMessage::Status(format!(
                                "Capture filter failed: Win32 error {error}"
                            )));
                        }
                    }
                    Ok(SourceCommand::Stop) | Err(TryRecvError::Disconnected) => {
                        unsafe { CloseHandle(handle) };
                        return;
                    }
                    Err(TryRecvError::Empty) => break,
                }
            }

            let mut bytes = 0_u32;
            let ok = unsafe {
                DeviceIoControl(
                    handle,
                    IOCTL_READ_EVENTS,
                    null(),
                    0,
                    event_buffer.as_mut_ptr() as *mut c_void,
                    (event_buffer.len() * size_of::<RawEvent>()) as u32,
                    &mut bytes,
                    null_mut(),
                )
            };
            if ok != 0 && bytes > 0 {
                let count = bytes as usize / size_of::<RawEvent>();
                let mut events = event_buffer[..count].to_vec();
                convert_qpc_to_local_seconds(&mut events, initial_stats.qpc_frequency);
                let _ = messages.send(SourceMessage::Events(events));
            }
            let mut detail_bytes = 0_u32;
            let detail_ok = unsafe {
                DeviceIoControl(
                    handle,
                    IOCTL_READ_DETAILS,
                    null(),
                    0,
                    detail_buffer.as_mut_ptr() as *mut c_void,
                    (detail_buffer.len() * size_of::<RawDetail>()) as u32,
                    &mut detail_bytes,
                    null_mut(),
                )
            };
            if detail_ok != 0 && detail_bytes > 0 {
                let count = detail_bytes as usize / size_of::<RawDetail>();
                let details = detail_buffer[..count]
                    .iter()
                    .map(|detail| (detail.sequence, detail.kind, detail.text()))
                    .collect();
                let _ = messages.send(SourceMessage::Details(details));
            }
            if last_stats.elapsed() >= Duration::from_millis(250) {
                send_stats(handle, &messages);
                last_stats = Instant::now();
            }
            if bytes == 0 && detail_bytes == 0 {
                thread::sleep(Duration::from_millis(1));
            }
        }
    }

    fn send_table(handle: *mut c_void, messages: &Sender<SourceMessage>) {
        let mut table = vec![unsafe { zeroed::<RawSyscallInfo>() }; MAX_SYSCALLS];
        let mut bytes = 0_u32;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_GET_TABLE,
                null(),
                0,
                table.as_mut_ptr() as *mut c_void,
                (table.len() * size_of::<RawSyscallInfo>()) as u32,
                &mut bytes,
                null_mut(),
            )
        };
        if ok != 0 {
            table.truncate(bytes as usize / size_of::<RawSyscallInfo>());
            let decoded = table
                .iter()
                .map(|entry| (entry.syscall_id, entry.category, entry.name()))
                .collect();
            let _ = messages.send(SourceMessage::SyscallTable(decoded));
        }
    }

    fn send_stats(handle: *mut c_void, messages: &Sender<SourceMessage>) {
        if let Some(stats) = query_stats(handle) {
            let _ = messages.send(SourceMessage::Stats(stats));
        }
    }

    fn query_stats(handle: *mut c_void) -> Option<DriverStats> {
        let mut stats = DriverStats::default();
        let mut bytes = 0_u32;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_GET_STATS,
                null(),
                0,
                &mut stats as *mut _ as *mut c_void,
                size_of::<DriverStats>() as u32,
                &mut bytes,
                null_mut(),
            )
        };
        (ok != 0 && bytes as usize == size_of::<DriverStats>()).then_some(stats)
    }

    fn convert_qpc_to_local_seconds(events: &mut [RawEvent], frequency: u64) {
        if frequency == 0 || events.is_empty() {
            return;
        }

        let mut now_qpc = 0_i64;
        let mut local = SYSTEMTIME::default();
        unsafe {
            QueryPerformanceCounter(&mut now_qpc);
            GetLocalTime(&mut local);
        }
        let now_millisecond = (i128::from(local.wHour) * 3_600
            + i128::from(local.wMinute) * 60
            + i128::from(local.wSecond))
            * 1_000
            + i128::from(local.wMilliseconds);
        let frequency = i128::from(frequency);
        for event in events {
            let delta_milliseconds =
                (i128::from(event.qpc) - i128::from(now_qpc)) * 1_000 / frequency;
            event.qpc = (now_millisecond + delta_milliseconds)
                .div_euclid(1_000)
                .rem_euclid(86_400) as u64;
        }
    }
}
