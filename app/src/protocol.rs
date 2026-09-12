pub const PROTOCOL_VERSION: u32 = 10;
pub const MAX_SYSCALLS: usize = 0x2000;
pub const MAX_TARGET_PIDS: usize = 16;
pub const MAX_TARGET_NAMES: usize = 16;
pub const PROCESS_NAME_BYTES: usize = 16;
pub const OPERATION_MASK_WORDS: usize = MAX_SYSCALLS / 32;
pub const UNKNOWN_RESULT: &str = "unknown";
pub const EVENT_FLAG_ARGUMENTS_VALID: u32 = 1;

pub const CATEGORIES: [&str; 12] = [
    "File", "Registry", "Process", "Thread", "Memory", "Security", "IPC", "Sync", "System",
    "Other", "User", "Graphics",
];
pub const ALL_CATEGORIES: u32 = (1 << CATEGORIES.len()) - 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RawEvent {
    pub qpc: u64,
    pub pid: u32,
    pub tid: u32,
    pub syscall_id: u16,
    pub category: u16,
    pub flags: u32,
    pub sequence: u64,
    pub arguments: [u64; 4],
    pub process_name: [u8; PROCESS_NAME_BYTES],
}

impl RawEvent {
    pub fn process_name(&self) -> Option<&str> {
        let length = self
            .process_name
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(self.process_name.len());
        std::str::from_utf8(&self.process_name[..length])
            .ok()
            .filter(|name| !name.is_empty())
    }

    pub fn raw_arguments(&self) -> String {
        format!(
            "0x{:X}, 0x{:X}, 0x{:X}, 0x{:X}",
            self.arguments[0], self.arguments[1], self.arguments[2], self.arguments[3]
        )
    }

    pub fn display_arguments(&self, operation: &str) -> String {
        if self.flags & EVENT_FLAG_ARGUMENTS_VALID == 0 {
            return "unavailable".to_owned();
        }
        let [a1, a2, a3, a4] = self.arguments;
        match operation {
            "NtClose" => format!("Handle=0x{a1:X}"),
            "NtRemoveIoCompletionEx" => {
                format!("Completion=0x{a1:X}, Buffer=0x{a2:X}, Count={a3}, Removed=0x{a4:X}")
            }
            "NtWaitForSingleObject" => {
                format!("Handle=0x{a1:X}, Alertable={}, Timeout=0x{a3:X}", a2 != 0)
            }
            "NtWaitForMultipleObjects" => format!(
                "Count={a1}, Handles=0x{a2:X}, WaitType={a3}, Alertable={}",
                a4 != 0
            ),
            "NtDelayExecution" => {
                format!("Alertable={}, Interval=0x{a2:X}", a1 != 0)
            }
            "NtSetEvent" | "NtResetEvent" => {
                format!("Event=0x{a1:X}, PreviousState=0x{a2:X}")
            }
            "NtReleaseSemaphore" => {
                format!("Semaphore=0x{a1:X}, ReleaseCount={a2}, PreviousCount=0x{a3:X}")
            }
            "NtReleaseMutant" => {
                format!("Mutant=0x{a1:X}, PreviousCount=0x{a2:X}")
            }
            "NtQueryObject" => {
                format!("Handle=0x{a1:X}, Class={a2}, Buffer=0x{a3:X}, BufferSize={a4}")
            }
            "NtDuplicateObject" => format!(
                "SourceProcess=0x{a1:X}, SourceHandle=0x{a2:X}, TargetProcess=0x{a3:X}, TargetHandle=0x{a4:X}"
            ),
            "NtSuspendProcess" | "NtResumeProcess" => format!("Process=0x{a1:X}"),
            "NtTerminateThread" => {
                format!("Thread=0x{a1:X}, ExitStatus=0x{a2:X}")
            }
            "NtQueryInformationThread" | "NtSetInformationThread" => {
                format!("Thread=0x{a1:X}, Class={a2}, Buffer=0x{a3:X}, BufferSize={a4}")
            }
            "NtQueryVirtualMemory" => {
                format!("Process=0x{a1:X}, Address=0x{a2:X}, Class={a3}, Buffer=0x{a4:X}")
            }
            "NtOpenProcessToken" => {
                format!("Process=0x{a1:X}, Access=0x{a2:X}, Token=0x{a3:X}")
            }
            "NtOpenProcessTokenEx" => {
                format!("Process=0x{a1:X}, Access=0x{a2:X}, Attributes=0x{a3:X}, Token=0x{a4:X}")
            }
            "NtQueryInformationToken" => {
                format!("Token=0x{a1:X}, Class={a2}, Buffer=0x{a3:X}, BufferSize={a4}")
            }
            "NtSetTimer" => {
                format!("Timer=0x{a1:X}, DueTime=0x{a2:X}, APC=0x{a3:X}, Context=0x{a4:X}")
            }
            "NtCancelTimer" => {
                format!("Timer=0x{a1:X}, CurrentState=0x{a2:X}")
            }
            "NtYieldExecution" | "NtTestAlert" => String::new(),
            _ => self.raw_arguments(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DriverConfig {
    pub version: u32,
    pub category_mask: u32,
    pub capture_enabled: u32,
    pub excluded_pid: u32,
    pub target_pid_count: u32,
    pub target_pids: [u32; MAX_TARGET_PIDS],
    pub target_name_count: u32,
    pub target_names: [[u8; PROCESS_NAME_BYTES]; MAX_TARGET_NAMES],
    pub operation_mask: [u32; OPERATION_MASK_WORDS],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DriverStats {
    pub version: u32,
    pub ring_capacity: u32,
    pub ring_queued: u32,
    pub reserved: u32,
    pub captured: u64,
    pub delivered: u64,
    pub dropped: u64,
    pub qpc_frequency: u64,
    pub details_dropped: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg(windows)]
pub struct RawSyscallInfo {
    pub syscall_id: u16,
    pub category: u16,
    pub name: [u8; 64],
}

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg(windows)]
pub struct RawDetail {
    pub sequence: u64,
    pub length: u16,
    pub kind: u16,
    pub text: [u8; 160],
}

#[cfg(windows)]
impl RawDetail {
    pub fn text(&self) -> String {
        let length = usize::from(self.length).min(self.text.len());
        String::from_utf8_lossy(&self.text[..length]).into_owned()
    }
}

#[cfg(windows)]
impl RawSyscallInfo {
    pub fn name(&self) -> String {
        let end = self
            .name
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(self.name.len());
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }
}

const _: () = assert!(size_of::<RawEvent>() == 80);
const _: () = assert!(size_of::<DriverConfig>() == 1368);
const _: () = assert!(size_of::<DriverStats>() == 56);
#[cfg(windows)]
const _: () = assert!(size_of::<RawDetail>() == 176);
