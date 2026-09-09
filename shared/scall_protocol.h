#pragma once

#define SCALL_DEVICE_NAME      L"\\Device\\ScallMonitor"
#define SCALL_DOS_DEVICE_NAME  L"\\DosDevices\\ScallMonitor"

#define SCALL_IOCTL_SET_CONFIG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA)
#define SCALL_IOCTL_READ_EVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_OUT_DIRECT, FILE_READ_DATA)
#define SCALL_IOCTL_GET_STATS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA)
#define SCALL_IOCTL_GET_TABLE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_OUT_DIRECT, FILE_READ_DATA)
#define SCALL_IOCTL_READ_DETAILS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_OUT_DIRECT, FILE_READ_DATA)

#define SCALL_PROTOCOL_VERSION 9u
#define SCALL_MAX_SYSCALLS 0x1000u
#define SCALL_MAX_TARGET_PIDS 16u
#define SCALL_MAX_TARGET_NAMES 16u
#define SCALL_PROCESS_NAME_BYTES 16u
#define SCALL_OPERATION_MASK_WORDS (SCALL_MAX_SYSCALLS / 32u)
#define SCALL_EVENT_FLAG_ARGUMENTS_VALID 0x1u

enum SCALL_CATEGORY : unsigned short {
    ScallCategoryFile = 0,
    ScallCategoryRegistry = 1,
    ScallCategoryProcess = 2,
    ScallCategoryThread = 3,
    ScallCategoryMemory = 4,
    ScallCategorySecurity = 5,
    ScallCategoryIpc = 6,
    ScallCategorySync = 7,
    ScallCategorySystem = 8,
    ScallCategoryOther = 9,
};

#define SCALL_ALL_CATEGORIES ((1u << 10) - 1u)

struct SCALL_EVENT {
    unsigned long long qpc;
    unsigned long pid;
    unsigned long tid;
    unsigned short syscall_id;
    unsigned short category;
    unsigned long flags;
    unsigned long long sequence;
    unsigned long long arguments[4];
    char process_name[SCALL_PROCESS_NAME_BYTES];
};

struct SCALL_CONFIG {
    unsigned long version;
    unsigned long category_mask;
    unsigned long capture_enabled;
    unsigned long excluded_pid;
    unsigned long target_pid_count;
    unsigned long target_pids[SCALL_MAX_TARGET_PIDS];
    unsigned long target_name_count;
    char target_names[SCALL_MAX_TARGET_NAMES][SCALL_PROCESS_NAME_BYTES];
    unsigned long operation_mask[SCALL_OPERATION_MASK_WORDS];
};

struct SCALL_STATS {
    unsigned long version;
    unsigned long ring_capacity;
    unsigned long ring_queued;
    unsigned long reserved;
    unsigned long long captured;
    unsigned long long delivered;
    unsigned long long dropped;
    unsigned long long qpc_frequency;
    unsigned long long details_dropped;
};

struct SCALL_SYSCALL_INFO {
    unsigned short syscall_id;
    unsigned short category;
    char name[64];
};

struct SCALL_DETAIL {
    unsigned long long sequence;
    unsigned short length;
    unsigned short kind;
    char text[160];
};
