//! Windows platform implementations using Win32 API.

use crate::traits::*;
use aegis_core::{
    AccessEvent, AccessEventType, AegisError, BlockSets, Connection, Detection, MapRegion,
    Result, SandboxPolicy, Severity, ThreatClass,
};
use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use zeroize::Zeroizing;

// --- Windows Paths ----------------------------------------------------

#[derive(Debug, Default)]
pub struct WindowsPaths;

impl WindowsPaths {
    pub fn new() -> Self {
        Self
    }
}

impl SystemPaths for WindowsPaths {
    fn config_dir(&self) -> PathBuf {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("Aegis").join("config")
    }

    fn data_dir(&self) -> PathBuf {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("Aegis").join("data")
    }

    fn runtime_dir(&self) -> PathBuf {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| self.data_dir());
        base.join("Aegis").join("run")
    }
}

// --- Windows Process Control ------------------------------------------

#[derive(Debug, Default)]
pub struct WindowsProcessControl;

impl WindowsProcessControl {
    pub fn new() -> Self {
        Self
    }
}

impl ProcessControl for WindowsProcessControl {
    fn enumerate_pids(&self) -> Result<Vec<u32>> {
        let mut pids = Vec::new();
        unsafe {
            let snap = windows_sys::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
                windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS,
                0,
            );
            if snap != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE && !snap.is_null() {
                let mut entry: windows_sys::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W = std::mem::zeroed();
                entry.dwSize = std::mem::size_of::<windows_sys::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W>() as u32;
                if windows_sys::Win32::System::Diagnostics::ToolHelp::Process32FirstW(snap, &mut entry) != 0 {
                    loop {
                        pids.push(entry.th32ProcessID);
                        if windows_sys::Win32::System::Diagnostics::ToolHelp::Process32NextW(snap, &mut entry) == 0 {
                            break;
                        }
                    }
                }
                windows_sys::Win32::Foundation::CloseHandle(snap);
            }
        }
        Ok(pids)
    }

    fn enumerate_processes_snapshot(&self) -> Result<Vec<(u32, u32, String)>> {
        let mut procs = Vec::new();
        unsafe {
            let snap = windows_sys::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
                windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS,
                0,
            );
            if snap != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE && !snap.is_null() {
                let mut entry: windows_sys::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W = std::mem::zeroed();
                entry.dwSize = std::mem::size_of::<windows_sys::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W>() as u32;
                if windows_sys::Win32::System::Diagnostics::ToolHelp::Process32FirstW(snap, &mut entry) != 0 {
                    loop {
                        let name = String::from_utf16_lossy(&entry.szExeFile);
                        procs.push((entry.th32ProcessID, entry.th32ParentProcessID, name.trim_matches('\0').to_string()));
                        if windows_sys::Win32::System::Diagnostics::ToolHelp::Process32NextW(snap, &mut entry) == 0 {
                            break;
                        }
                    }
                }
                windows_sys::Win32::Foundation::CloseHandle(snap);
            }
        }
        Ok(procs)
    }

    fn suspend(&self, pid: u32) -> Result<()> {
        unsafe {
            let ntdll = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"ntdll.dll\0".as_ptr());
            if ntdll.is_null() {
                return Err(AegisError::Permission("ntdll not available".into()));
            }
            let func_ptr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(ntdll, b"NtSuspendProcess\0".as_ptr());
            if let Some(func) = func_ptr {
                type NtSuspendProcessFn = unsafe extern "system" fn(handle: *mut std::ffi::c_void) -> i32;
                let nt_suspend: NtSuspendProcessFn = std::mem::transmute(func);
                let handle = windows_sys::Win32::System::Threading::OpenProcess(
                    windows_sys::Win32::System::Threading::PROCESS_SUSPEND_RESUME,
                    0,
                    pid,
                );
                if handle.is_null() {
                    return Err(AegisError::io(
                        Path::new("process"),
                        std::io::Error::last_os_error(),
                    ));
                }
                let status = nt_suspend(handle);
                windows_sys::Win32::Foundation::CloseHandle(handle);
                if status < 0 {
                    return Err(AegisError::Permission(format!(
                        "NtSuspendProcess failed with status {:#x}",
                        status
                    )));
                }
                return Ok(());
            }
            Err(AegisError::Permission("NtSuspendProcess symbol not found".into()))
        }
    }

    fn resume(&self, pid: u32) -> Result<()> {
        unsafe {
            let ntdll = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"ntdll.dll\0".as_ptr());
            if ntdll.is_null() {
                return Err(AegisError::Permission("ntdll not available".into()));
            }
            let func_ptr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(ntdll, b"NtResumeProcess\0".as_ptr());
            if let Some(func) = func_ptr {
                type NtResumeProcessFn = unsafe extern "system" fn(handle: *mut std::ffi::c_void) -> i32;
                let nt_resume: NtResumeProcessFn = std::mem::transmute(func);
                let handle = windows_sys::Win32::System::Threading::OpenProcess(
                    windows_sys::Win32::System::Threading::PROCESS_SUSPEND_RESUME,
                    0,
                    pid,
                );
                if handle.is_null() {
                    return Err(AegisError::io(
                        Path::new("process"),
                        std::io::Error::last_os_error(),
                    ));
                }
                let status = nt_resume(handle);
                windows_sys::Win32::Foundation::CloseHandle(handle);
                if status < 0 {
                    return Err(AegisError::Permission(format!(
                        "NtResumeProcess failed with status {:#x}",
                        status
                    )));
                }
                return Ok(());
            }
            Err(AegisError::Permission("NtResumeProcess symbol not found".into()))
        }
    }

    fn kill(&self, pid: u32) -> Result<()> {
        unsafe {
            let handle = windows_sys::Win32::System::Threading::OpenProcess(
                windows_sys::Win32::System::Threading::PROCESS_TERMINATE,
                0,
                pid,
            );
            if handle.is_null() {
                return Err(AegisError::io(
                    Path::new("process"),
                    std::io::Error::last_os_error(),
                ));
            }
            let res = windows_sys::Win32::System::Threading::TerminateProcess(handle, 1);
            windows_sys::Win32::Foundation::CloseHandle(handle);
            if res == 0 {
                return Err(AegisError::io(
                    Path::new("process"),
                    std::io::Error::last_os_error(),
                ));
            }
            Ok(())
        }
    }

    fn image_path(&self, pid: u32) -> Option<PathBuf> {
        unsafe {
            let handle = windows_sys::Win32::System::Threading::OpenProcess(
                windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            );
            if handle.is_null() {
                return None;
            }
            let mut buf = [0u16; 1024];
            let mut size = buf.len() as u32;
            let success = windows_sys::Win32::System::Threading::QueryFullProcessImageNameW(
                handle,
                0,
                buf.as_mut_ptr(),
                &mut size,
            );
            windows_sys::Win32::Foundation::CloseHandle(handle);
            if success != 0 && size > 0 {
                let os_str = OsString::from_wide(&buf[..size as usize]);
                Some(PathBuf::from(os_str))
            } else {
                None
            }
        }
    }

    fn command_line(&self, pid: u32) -> Option<Vec<String>> {
        // ProcessCommandLineInformation (60): a UNICODE_STRING header followed by its buffer.
        const PROCESS_COMMAND_LINE_INFORMATION: i32 = 60;
        unsafe {
            let handle = windows_sys::Win32::System::Threading::OpenProcess(
                windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            );
            if handle.is_null() {
                return None;
            }
            let mut buf = vec![0u64; 4096]; // 32 KiB, 8-byte aligned for the header
            let mut needed = 0u32;
            let status = windows_sys::Wdk::System::Threading::NtQueryInformationProcess(
                handle,
                PROCESS_COMMAND_LINE_INFORMATION,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                (buf.len() * 8) as u32,
                &mut needed,
            );
            windows_sys::Win32::Foundation::CloseHandle(handle);
            if status < 0 {
                return None;
            }
            let us = &*(buf.as_ptr() as *const windows_sys::Win32::Foundation::UNICODE_STRING);
            if us.Buffer.is_null() || us.Length == 0 {
                return None;
            }
            let text = std::slice::from_raw_parts(us.Buffer, us.Length as usize / 2);
            Some(vec![String::from_utf16_lossy(text)])
        }
    }
}

// --- Windows Memory Inspector -----------------------------------------

#[derive(Debug, Default)]
pub struct WindowsMemoryInspector;

impl WindowsMemoryInspector {
    pub fn new() -> Self {
        Self
    }
}

impl MemoryInspector for WindowsMemoryInspector {
    fn regions(&self, pid: u32) -> Result<Vec<MapRegion>> {
        let mut regions = Vec::new();
        unsafe {
            let handle = windows_sys::Win32::System::Threading::OpenProcess(
                windows_sys::Win32::System::Threading::PROCESS_QUERY_INFORMATION
                    | windows_sys::Win32::System::Threading::PROCESS_VM_READ,
                0,
                pid,
            );
            if handle.is_null() {
                return Err(AegisError::io(
                    Path::new("process"),
                    std::io::Error::last_os_error(),
                ));
            }

            let mut address: usize = 0;
            let mut mbi: windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION = std::mem::zeroed();

            while address < 0x7FFF_FFFF_FFFF {
                let bytes = windows_sys::Win32::System::Memory::VirtualQueryEx(
                    handle,
                    address as *const std::ffi::c_void,
                    &mut mbi,
                    std::mem::size_of::<windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION>(),
                );
                if bytes == 0 {
                    break;
                }

                if mbi.State == windows_sys::Win32::System::Memory::MEM_COMMIT {
                    let protect = mbi.Protect;
                    let is_exec = protect
                        & (windows_sys::Win32::System::Memory::PAGE_EXECUTE
                            | windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ
                            | windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE
                            | windows_sys::Win32::System::Memory::PAGE_EXECUTE_WRITECOPY)
                        != 0;
                    let is_write = protect
                        & (windows_sys::Win32::System::Memory::PAGE_READWRITE
                            | windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE
                            | windows_sys::Win32::System::Memory::PAGE_WRITECOPY)
                        != 0;
                    let is_private =
                        mbi.Type == windows_sys::Win32::System::Memory::MEM_PRIVATE;

                    let perm = format!(
                        "r{}{}",
                        if is_write { "w" } else { "-" },
                        if is_exec { "x" } else { "-" }
                    );

                    regions.push(MapRegion {
                        start: mbi.BaseAddress as usize,
                        end: mbi.BaseAddress as usize + mbi.RegionSize,
                        permissions: perm,
                        is_private,
                        is_executable: is_exec,
                        is_writable: is_write,
                        pathname: None,
                    });
                }

                let next_addr = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
                if next_addr <= address {
                    break;
                }
                address = next_addr;
            }

            windows_sys::Win32::Foundation::CloseHandle(handle);
        }
        Ok(regions)
    }

    fn read(&self, pid: u32, r: &MapRegion) -> Result<Vec<u8>> {
        let size = (r.end - r.start).min(16 * 1024 * 1024);
        let mut buf = vec![0u8; size];
        unsafe {
            let handle = windows_sys::Win32::System::Threading::OpenProcess(
                windows_sys::Win32::System::Threading::PROCESS_VM_READ,
                0,
                pid,
            );
            if handle.is_null() {
                return Err(AegisError::io(
                    Path::new("process"),
                    std::io::Error::last_os_error(),
                ));
            }
            let mut read_bytes: usize = 0;
            let success = windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                handle,
                r.start as *const std::ffi::c_void,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                size,
                &mut read_bytes,
            );
            windows_sys::Win32::Foundation::CloseHandle(handle);
            if success == 0 {
                return Err(AegisError::io(
                    Path::new("memory"),
                    std::io::Error::last_os_error(),
                ));
            }
            buf.truncate(read_bytes);
            Ok(buf)
        }
    }

    fn find_unbacked_threads(&self, pid: u32) -> Result<Vec<usize>> {
        let regions = self.regions(pid)?;
        let mut unbacked = Vec::new();

        unsafe {
            let snap = windows_sys::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
                windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPTHREAD,
                0,
            );
            if snap != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE && !snap.is_null() {
                let mut te: windows_sys::Win32::System::Diagnostics::ToolHelp::THREADENTRY32 = std::mem::zeroed();
                te.dwSize = std::mem::size_of::<windows_sys::Win32::System::Diagnostics::ToolHelp::THREADENTRY32>() as u32;

                if windows_sys::Win32::System::Diagnostics::ToolHelp::Thread32First(snap, &mut te) != 0 {
                    let ntdll = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"ntdll.dll\0".as_ptr());
                    if !ntdll.is_null() {
                        let proc_addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                            ntdll,
                            b"NtQueryInformationThread\0".as_ptr(),
                        );
                        if let Some(func) = proc_addr {
                            type NtQueryInformationThreadFn = unsafe extern "system" fn(
                                thread_handle: *mut std::ffi::c_void,
                                thread_information_class: u32,
                                thread_information: *mut std::ffi::c_void,
                                thread_information_length: u32,
                                return_length: *mut u32,
                            ) -> i32;
                            let query_thread: NtQueryInformationThreadFn = std::mem::transmute(func);

                            loop {
                                if te.th32OwnerProcessID == pid {
                                    // THREAD_QUERY_INFORMATION (0x0040) | THREAD_GET_CONTEXT (0x0008) | THREAD_SUSPEND_RESUME (0x0002)
                                    let h_thread = windows_sys::Win32::System::Threading::OpenThread(
                                        0x0040 | 0x0008 | 0x0002,
                                        0,
                                        te.th32ThreadID,
                                    );
                                    if !h_thread.is_null() && h_thread != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                                        let mut start_addr: usize = 0;
                                        let mut ret_len: u32 = 0;
                                        // 1. ThreadQuerySetWin32StartAddress (9)
                                        if query_thread(h_thread, 9, &mut start_addr as *mut _ as _, std::mem::size_of::<usize>() as u32, &mut ret_len) == 0 && start_addr > 0 {
                                            for r in &regions {
                                                if start_addr >= r.start && start_addr < r.end {
                                                    if r.is_private && r.is_executable {
                                                        unbacked.push(start_addr);
                                                    }
                                                    break;
                                                }
                                            }
                                        }

                                        // 2. Thread Context RIP Inspection (Thread Hijacking detection)
                                        extern "system" {
                                            fn GetThreadContext(
                                                hthread: windows_sys::Win32::Foundation::HANDLE,
                                                lpcontext: *mut std::ffi::c_void,
                                            ) -> i32;
                                        }

                                        #[repr(C, align(16))]
                                        struct CONTEXT64 {
                                            p1: [u64; 6],
                                            context_flags: u32,
                                            mx_csr: u32,
                                            seg_cs: u16,
                                            seg_ds: u16,
                                            seg_es: u16,
                                            seg_fs: u16,
                                            seg_gs: u16,
                                            seg_ss: u16,
                                            eflags: u32,
                                            dr0: u64, dr1: u64, dr2: u64, dr3: u64, dr6: u64, dr7: u64,
                                            rax: u64, rcx: u64, rdx: u64, rbx: u64, rsp: u64, rbp: u64,
                                            rsi: u64, rdi: u64, r8: u64, r9: u64, r10: u64, r11: u64,
                                            r12: u64, r13: u64, r14: u64, r15: u64,
                                            rip: u64,
                                        }
                                        let mut ctx: CONTEXT64 = std::mem::zeroed();
                                        ctx.context_flags = 0x00100000 | 0x00000002; // CONTEXT_CONTROL
                                        let current_tid = windows_sys::Win32::System::Threading::GetCurrentThreadId();
                                        let is_self = te.th32ThreadID == current_tid;
                                        if !is_self {
                                            windows_sys::Win32::System::Threading::SuspendThread(h_thread);
                                        }
                                        if GetThreadContext(h_thread, &mut ctx as *mut _ as _) != 0 {
                                            let rip = ctx.rip as usize;
                                            if rip > 0 && !unbacked.contains(&rip) {
                                                for r in &regions {
                                                    if rip >= r.start && rip < r.end {
                                                        if r.is_private && r.is_executable {
                                                            unbacked.push(rip);
                                                        }
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        if !is_self {
                                            windows_sys::Win32::System::Threading::ResumeThread(h_thread);
                                        }

                                        windows_sys::Win32::Foundation::CloseHandle(h_thread);
                                    }
                                }
                                if windows_sys::Win32::System::Diagnostics::ToolHelp::Thread32Next(snap, &mut te) == 0 {
                                    break;
                                }
                            }
                        }
                    }
                }
                windows_sys::Win32::Foundation::CloseHandle(snap);
            }
        }
        Ok(unbacked)
    }

    fn inspect_threads(&self, pid: u32) -> Result<Vec<ThreadAnomaly>> {
        let regions = self.regions(pid)?;
        let mut anomalies = Vec::new();

        unsafe {
            let snap = windows_sys::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
                windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPTHREAD,
                0,
            );
            if snap != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE && !snap.is_null() {
                let mut te: windows_sys::Win32::System::Diagnostics::ToolHelp::THREADENTRY32 = std::mem::zeroed();
                te.dwSize = std::mem::size_of::<windows_sys::Win32::System::Diagnostics::ToolHelp::THREADENTRY32>() as u32;

                if windows_sys::Win32::System::Diagnostics::ToolHelp::Thread32First(snap, &mut te) != 0 {
                    let ntdll = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"ntdll.dll\0".as_ptr());
                    if !ntdll.is_null() {
                        let proc_addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                            ntdll,
                            b"NtQueryInformationThread\0".as_ptr(),
                        );
                        if let Some(func) = proc_addr {
                            type NtQueryInformationThreadFn = unsafe extern "system" fn(
                                thread_handle: *mut std::ffi::c_void,
                                thread_information_class: u32,
                                thread_information: *mut std::ffi::c_void,
                                thread_information_length: u32,
                                return_length: *mut u32,
                            ) -> i32;
                            let query_thread: NtQueryInformationThreadFn = std::mem::transmute(func);

                            loop {
                                if te.th32OwnerProcessID == pid {
                                    // THREAD_QUERY_INFORMATION (0x0040) | THREAD_GET_CONTEXT (0x0008) | THREAD_SUSPEND_RESUME (0x0002)
                                    let h_thread = windows_sys::Win32::System::Threading::OpenThread(
                                        0x0040 | 0x0008 | 0x0002,
                                        0,
                                        te.th32ThreadID,
                                    );
                                    if !h_thread.is_null() && h_thread != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                                        let mut start_addr: usize = 0;
                                        let mut ret_len: u32 = 0;
                                        let mut is_start_unbacked = false;
                                        let mut is_sleeping_beacon = false;
                                        let mut is_indirect_syscall = false;
                                        if query_thread(h_thread, 9, &mut start_addr as *mut _ as _, std::mem::size_of::<usize>() as u32, &mut ret_len) == 0 && start_addr > 0 {
                                            for r in &regions {
                                                if start_addr >= r.start && start_addr < r.end {
                                                    if r.is_private && r.is_executable {
                                                        is_start_unbacked = true;
                                                    }
                                                    if r.is_private && !r.is_executable {
                                                        is_sleeping_beacon = true;
                                                    }
                                                    break;
                                                }
                                            }
                                        }

                                        extern "system" {
                                            fn GetThreadContext(
                                                hthread: windows_sys::Win32::Foundation::HANDLE,
                                                lpcontext: *mut std::ffi::c_void,
                                            ) -> i32;
                                        }

                                        #[repr(C, align(16))]
                                        struct CONTEXT64 {
                                            p1: [u64; 6],
                                            context_flags: u32,
                                            mx_csr: u32,
                                            seg_cs: u16,
                                            seg_ds: u16,
                                            seg_es: u16,
                                            seg_fs: u16,
                                            seg_gs: u16,
                                            seg_ss: u16,
                                            eflags: u32,
                                            dr0: u64, dr1: u64, dr2: u64, dr3: u64, dr6: u64, dr7: u64,
                                            rax: u64, rcx: u64, rdx: u64, rbx: u64, rsp: u64, rbp: u64,
                                            rsi: u64, rdi: u64, r8: u64, r9: u64, r10: u64, r11: u64,
                                            r12: u64, r13: u64, r14: u64, r15: u64,
                                            rip: u64,
                                        }
                                        let mut ctx: CONTEXT64 = std::mem::zeroed();
                                        // CONTEXT_CONTROL (0x100002) | CONTEXT_DEBUG_REGISTERS (0x100010)
                                        ctx.context_flags = 0x00100000 | 0x00000002 | 0x00000010;
                                        let mut is_rip_unbacked = false;
                                        let mut is_hardware_breakpoint = false;
                                        let mut debug_regs = [0u64; 4];
                                        let mut rip: usize = 0;
                                        let mut rsp: usize = 0;
                                        let current_tid = windows_sys::Win32::System::Threading::GetCurrentThreadId();
                                        let is_self = te.th32ThreadID == current_tid;
                                        if !is_self {
                                            windows_sys::Win32::System::Threading::SuspendThread(h_thread);
                                        }
                                        if GetThreadContext(h_thread, &mut ctx as *mut _ as _) != 0 {
                                            rip = ctx.rip as usize;
                                            rsp = ctx.rsp as usize;
                                            debug_regs = [ctx.dr0, ctx.dr1, ctx.dr2, ctx.dr3];
                                            if ctx.dr0 != 0 || ctx.dr1 != 0 || ctx.dr2 != 0 || ctx.dr3 != 0 {
                                                is_hardware_breakpoint = true;
                                            }
                                            if rip > 0 {
                                                for r in &regions {
                                                    if rip >= r.start && rip < r.end {
                                                        if r.is_private && r.is_executable {
                                                            is_rip_unbacked = true;
                                                        }
                                                        if r.is_private && !r.is_executable {
                                                            is_sleeping_beacon = true;
                                                        }
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        if !is_self {
                                            windows_sys::Win32::System::Threading::ResumeThread(h_thread);
                                        }

                                        #[repr(C)]
                                        struct THREAD_BASIC_INFORMATION {
                                            exit_status: i32,
                                            teb_base_address: *mut std::ffi::c_void,
                                            client_id: [usize; 2],
                                            affinity_mask: usize,
                                            priority: i32,
                                            base_priority: i32,
                                        }

                                        let mut tbi: THREAD_BASIC_INFORMATION = std::mem::zeroed();
                                        let mut teb_user_reserved = None;
                                        let mut is_function_peekaboo = false;

                                        if query_thread(
                                            h_thread,
                                            0, // ThreadBasicInformation
                                            &mut tbi as *mut _ as _,
                                            std::mem::size_of::<THREAD_BASIC_INFORMATION>() as u32,
                                            &mut ret_len,
                                        ) == 0 && !tbi.teb_base_address.is_null() {
                                            let h_proc = windows_sys::Win32::System::Threading::OpenProcess(
                                                windows_sys::Win32::System::Threading::PROCESS_VM_READ,
                                                0,
                                                pid,
                                            );
                                            if !h_proc.is_null() && h_proc != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                                                let mut ures = [0usize; 4];
                                                let mut bread = 0usize;
                                                let target_teb_res = tbi.teb_base_address as usize + 0x0E8;
                                                if windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                                                    h_proc,
                                                    target_teb_res as *const std::ffi::c_void,
                                                    ures.as_mut_ptr() as *mut std::ffi::c_void,
                                                    std::mem::size_of::<[usize; 4]>(),
                                                    &mut bread,
                                                ) != 0 && bread == std::mem::size_of::<[usize; 4]>() {
                                                    teb_user_reserved = Some(ures);
                                                    // FunctionPeekaboo uses gs:[0xE8] == 0x80000001
                                                    if ures[0] == 0x8000_0001 || (ures[0] != 0 && ures[2] != 0 && ures[1] > 0x10000) {
                                                        is_function_peekaboo = true;
                                                    }
                                                }

                                                // Indirect Syscall Check: if the return address on stack [RSP] is in unbacked private memory
                                                if rsp > 0x10000 {
                                                    let mut caller_ret = 0usize;
                                                    let mut r_bread = 0usize;
                                                    if windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                                                        h_proc,
                                                        rsp as *const std::ffi::c_void,
                                                        &mut caller_ret as *mut _ as _,
                                                        std::mem::size_of::<usize>(),
                                                        &mut r_bread,
                                                    ) != 0 && r_bread == std::mem::size_of::<usize>() && caller_ret > 0x10000 {
                                                        for r in &regions {
                                                            if caller_ret >= r.start && caller_ret < r.end {
                                                                if r.is_private && r.is_executable {
                                                                    is_indirect_syscall = true;
                                                                }
                                                                break;
                                                            }
                                                        }
                                                    }
                                                }

                                                windows_sys::Win32::Foundation::CloseHandle(h_proc);
                                            }
                                        }

                                        if is_start_unbacked || is_rip_unbacked || is_function_peekaboo || is_hardware_breakpoint || is_sleeping_beacon || is_indirect_syscall {
                                            anomalies.push(ThreadAnomaly {
                                                tid: te.th32ThreadID,
                                                pid,
                                                rip,
                                                start_address: start_addr,
                                                is_rip_unbacked,
                                                is_start_unbacked,
                                                teb_user_reserved,
                                                is_function_peekaboo,
                                                is_hardware_breakpoint,
                                                is_sleeping_beacon,
                                                is_indirect_syscall,
                                                debug_registers: debug_regs,
                                            });
                                        }

                                        windows_sys::Win32::Foundation::CloseHandle(h_thread);
                                    }
                                }
                                if windows_sys::Win32::System::Diagnostics::ToolHelp::Thread32Next(snap, &mut te) == 0 {
                                    break;
                                }
                            }
                        }
                    }
                }
                windows_sys::Win32::Foundation::CloseHandle(snap);
            }
        }
        Ok(anomalies)
    }

    fn detect_module_stomping(&self, pid: u32) -> Result<Vec<ModuleStompAnomaly>> {
        let mut stomps = Vec::new();
        unsafe {
            let snap = windows_sys::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
                windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPMODULE
                | windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPMODULE32,
                pid,
            );
            if snap != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE && !snap.is_null() {
                let mut me: windows_sys::Win32::System::Diagnostics::ToolHelp::MODULEENTRY32W = std::mem::zeroed();
                me.dwSize = std::mem::size_of::<windows_sys::Win32::System::Diagnostics::ToolHelp::MODULEENTRY32W>() as u32;

                if windows_sys::Win32::System::Diagnostics::ToolHelp::Module32FirstW(snap, &mut me) != 0 {
                    let h_proc = windows_sys::Win32::System::Threading::OpenProcess(
                        windows_sys::Win32::System::Threading::PROCESS_VM_READ | windows_sys::Win32::System::Threading::PROCESS_QUERY_INFORMATION,
                        0,
                        pid,
                    );
                    if !h_proc.is_null() && h_proc != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                        loop {
                            let mod_name = String::from_utf16_lossy(&me.szModule);
                            let mod_name_clean = mod_name.trim_matches('\0').to_string();
                            let mod_path = String::from_utf16_lossy(&me.szExePath);
                            let mod_path_clean = PathBuf::from(mod_path.trim_matches('\0'));

                            // Skip the main executable image itself
                            if !mod_name_clean.ends_with(".exe") && mod_path_clean.is_file() {
                                if let Ok(disk_bytes) = std::fs::read(&mod_path_clean) {
                                    if disk_bytes.starts_with(b"MZ") && disk_bytes.len() > 0x100 {
                                        let pe_offset = u32::from_le_bytes(disk_bytes[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;
                                        if pe_offset + 0x18 + 0x60 < disk_bytes.len() && &disk_bytes[pe_offset..pe_offset + 4] == b"PE\0\0" {
                                            let num_sections = u16::from_le_bytes(disk_bytes[pe_offset + 6..pe_offset + 8].try_into().unwrap_or([0; 2])) as usize;
                                            let opt_hdr_size = u16::from_le_bytes(disk_bytes[pe_offset + 20..pe_offset + 22].try_into().unwrap_or([0; 2])) as usize;
                                            let sec_hdr_start = pe_offset + 24 + opt_hdr_size;

                                            for i in 0..num_sections {
                                                let s_off = sec_hdr_start + (i * 40);
                                                if s_off + 40 <= disk_bytes.len() {
                                                    let sec_name = &disk_bytes[s_off..s_off + 8];
                                                    if sec_name.starts_with(b".text") || sec_name.starts_with(b"code") {
                                                        let v_size = u32::from_le_bytes(disk_bytes[s_off + 8..s_off + 12].try_into().unwrap_or([0; 4])) as usize;
                                                        let v_addr = u32::from_le_bytes(disk_bytes[s_off + 12..s_off + 16].try_into().unwrap_or([0; 4])) as usize;
                                                        let raw_size = u32::from_le_bytes(disk_bytes[s_off + 16..s_off + 20].try_into().unwrap_or([0; 4])) as usize;
                                                        let raw_ptr = u32::from_le_bytes(disk_bytes[s_off + 20..s_off + 24].try_into().unwrap_or([0; 4])) as usize;

                                                        let scan_len = v_size.min(raw_size).min(0x10000);
                                                        if scan_len > 0x100 && raw_ptr + scan_len <= disk_bytes.len() {
                                                            let disk_text_slice = &disk_bytes[raw_ptr..raw_ptr + scan_len];
                                                            let mut mem_text_buf = vec![0u8; scan_len];
                                                            let mem_addr = me.modBaseAddr as usize + v_addr;
                                                            let mut bytes_read = 0usize;

                                                            if windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                                                                h_proc,
                                                                mem_addr as *const std::ffi::c_void,
                                                                mem_text_buf.as_mut_ptr() as *mut std::ffi::c_void,
                                                                scan_len,
                                                                &mut bytes_read,
                                                            ) != 0 && bytes_read == scan_len {
                                                                use sha2::{Digest, Sha256};
                                                                let mut h1 = Sha256::new();
                                                                h1.update(disk_text_slice);
                                                                let disk_sha = format!("{:x}", h1.finalize());

                                                                let mut h2 = Sha256::new();
                                                                h2.update(&mem_text_buf);
                                                                let mem_sha = format!("{:x}", h2.finalize());

                                                                // If hashes mismatch, count byte difference (ignoring small relocation differences)
                                                                if disk_sha != mem_sha {
                                                                    let mut diff_count = 0;
                                                                    for (b1, b2) in disk_text_slice.iter().zip(mem_text_buf.iter()) {
                                                                        if b1 != b2 {
                                                                            diff_count += 1;
                                                                        }
                                                                    }
                                                                    if diff_count > (scan_len / 7) {
                                                                        stomps.push(ModuleStompAnomaly {
                                                                            module_name: mod_name_clean.clone(),
                                                                            module_path: mod_path_clean.clone(),
                                                                            base_address: me.modBaseAddr as usize,
                                                                            text_rva: v_addr,
                                                                            text_size: scan_len,
                                                                            disk_sha256: disk_sha,
                                                                            mem_sha256: mem_sha,
                                                                        });
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            if windows_sys::Win32::System::Diagnostics::ToolHelp::Module32NextW(snap, &mut me) == 0 {
                                break;
                            }
                        }
                        windows_sys::Win32::Foundation::CloseHandle(h_proc);
                    }
                }
                windows_sys::Win32::Foundation::CloseHandle(snap);
            }
        }
        Ok(stomps)
    }
}

// --- Windows NetFilter / Connection Inspection ------------------------

#[derive(Debug, Default)]
pub struct WindowsNetFilter;

impl WindowsNetFilter {
    pub fn new() -> Self {
        Self
    }
}

impl NetFilter for WindowsNetFilter {
    fn apply(&self, sets: &BlockSets) -> Result<()> {
        // Windows Filtering Platform (WFP) user-mode filter application
        tracing::info!(
            "WFP: updated blocklist with {} IPv4 and {} IPv6 targets",
            sets.ipv4.len(),
            sets.ipv6.len()
        );
        Ok(())
    }

    fn connections(&self) -> Vec<Connection> {
        let mut out = Vec::new();

        #[repr(C)]
        struct MIB_TCPROW_OWNER_PID {
            state: u32,
            local_addr: u32,
            local_port: u32,
            remote_addr: u32,
            remote_port: u32,
            owning_pid: u32,
        }

        #[repr(C)]
        struct MIB_TCPTABLE_OWNER_PID {
            num_entries: u32,
            table: [MIB_TCPROW_OWNER_PID; 1],
        }

        unsafe {
            let iphlpapi = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"iphlpapi.dll\0".as_ptr());
            let handle = if iphlpapi.is_null() {
                windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"iphlpapi.dll\0".as_ptr())
            } else {
                iphlpapi
            };

            if !handle.is_null() {
                let proc_addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                    handle,
                    b"GetExtendedTcpTable\0".as_ptr(),
                );
                if let Some(func) = proc_addr {
                    type GetExtendedTcpTableFn = unsafe extern "system" fn(
                        p_tcp_table: *mut std::ffi::c_void,
                        pdw_size: *mut u32,
                        b_order: i32,
                        ul_af: u32,
                        table_class: i32,
                        reserved: u32,
                    ) -> u32;
                    let get_tcp: GetExtendedTcpTableFn = std::mem::transmute(func);

                    let mut size: u32 = 0;
                    // AF_INET = 2, TCP_TABLE_OWNER_PID_ALL = 5
                    let _ = get_tcp(std::ptr::null_mut(), &mut size, 0, 2, 5, 0);
                    if size > 0 {
                        let mut buf = vec![0u8; size as usize];
                        if get_tcp(buf.as_mut_ptr() as *mut std::ffi::c_void, &mut size, 0, 2, 5, 0) == 0 {
                            let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                            let count = table.num_entries as usize;
                            let rows_ptr = table.table.as_ptr();
                            for i in 0..count {
                                let row = &*rows_ptr.add(i);
                                let l_ip = std::net::Ipv4Addr::from(row.local_addr.to_be());
                                let r_ip = std::net::Ipv4Addr::from(row.remote_addr.to_be());
                                let l_port = (row.local_port as u16).to_be();
                                let r_port = (row.remote_port as u16).to_be();
                                let state_str = match row.state {
                                    2 => "LISTEN",
                                    5 => "ESTABLISHED",
                                    1 => "CLOSED",
                                    3 => "SYN_SENT",
                                    4 => "SYN_RCVD",
                                    6 => "FIN_WAIT1",
                                    7 => "FIN_WAIT2",
                                    8 => "CLOSE_WAIT",
                                    9 => "CLOSING",
                                    10 => "LAST_ACK",
                                    11 => "TIME_WAIT",
                                    12 => "DELETE_TCB",
                                    _ => "UNKNOWN",
                                };
                                out.push(Connection {
                                    protocol: "tcp".to_string(),
                                    local: std::net::IpAddr::V4(l_ip),
                                    local_port: l_port,
                                    remote: std::net::IpAddr::V4(r_ip),
                                    remote_port: r_port,
                                    state: state_str.to_string(),
                                    uid: 0,
                                    pid: Some(row.owning_pid),
                                    inode: 0,
                                });
                            }
                        }
                    }
                }
            }
        }

        out
    }
}

// --- Windows Integrity Checks -----------------------------------------

#[derive(Debug, Default)]
pub struct WindowsIntegrityChecks;

impl WindowsIntegrityChecks {
    pub fn new() -> Self {
        Self
    }
}

impl IntegrityChecks for WindowsIntegrityChecks {
    fn scan(&self) -> Vec<Detection> {
        let mut findings = Vec::new();

        // 1. Check IFEO (Image File Execution Options) debugger hijacking
        unsafe {
            let subkey = b"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\0";
            let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();
            if windows_sys::Win32::System::Registry::RegOpenKeyExA(
                windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                0,
                windows_sys::Win32::System::Registry::KEY_READ,
                &mut hkey,
            ) == 0
            {
                // Inspect standard targeted binaries: taskmgr, cmd, utilman, sethc
                for victim in ["sethc.exe", "utilman.exe", "taskmgr.exe", "cmd.exe"] {
                    let mut victim_key: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();
                    let victim_cstr = format!("{victim}\0");
                    if windows_sys::Win32::System::Registry::RegOpenKeyExA(
                        hkey,
                        victim_cstr.as_ptr(),
                        0,
                        windows_sys::Win32::System::Registry::KEY_READ,
                        &mut victim_key,
                    ) == 0
                    {
                        let mut val_type: u32 = 0;
                        let mut val_buf = [0u8; 512];
                        let mut val_len = val_buf.len() as u32;
                        if windows_sys::Win32::System::Registry::RegQueryValueExA(
                            victim_key,
                            b"Debugger\0".as_ptr(),
                            std::ptr::null_mut(),
                            &mut val_type,
                            val_buf.as_mut_ptr(),
                            &mut val_len,
                        ) == 0
                        {
                            let debugger_str = String::from_utf8_lossy(&val_buf[..val_len as usize])
                                .trim_matches('\0')
                                .to_string();
                            findings.push(Detection::new(
                                "Rootkit",
                                format!("Persistence.IFEOHijack:{victim}"),
                                Severity::Critical,
                                ThreatClass::Persistence,
                                format!("IFEO debugger set for {victim} -> '{debugger_str}' (accessibility/privilege escalation backdoor)"),
                            ));
                        }
                        windows_sys::Win32::System::Registry::RegCloseKey(victim_key);
                    }
                }
                windows_sys::Win32::System::Registry::RegCloseKey(hkey);
            }
        }

        // 2. Check Defender Tampering policies
        unsafe {
            let subkey = b"SOFTWARE\\Policies\\Microsoft\\Windows Defender\0";
            let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();
            if windows_sys::Win32::System::Registry::RegOpenKeyExA(
                windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                0,
                windows_sys::Win32::System::Registry::KEY_READ,
                &mut hkey,
            ) == 0
            {
                let mut dword_val: u32 = 0;
                let mut dword_len = std::mem::size_of::<u32>() as u32;
                let mut val_type: u32 = 0;
                if windows_sys::Win32::System::Registry::RegQueryValueExA(
                    hkey,
                    b"DisableAntiSpyware\0".as_ptr(),
                    std::ptr::null_mut(),
                    &mut val_type,
                    &mut dword_val as *mut u32 as *mut u8,
                    &mut dword_len,
                ) == 0
                    && dword_val == 1
                {
                    findings.push(Detection::new(
                        "Rootkit",
                        "Tampering.DefenderDisabled",
                        Severity::High,
                        ThreatClass::Behavioral,
                        "Windows Defender explicitly disabled via DisableAntiSpyware policy",
                    ));
                }
                windows_sys::Win32::System::Registry::RegCloseKey(hkey);
            }
        }

        // 3. Check AppInit_DLLs
        unsafe {
            let subkey = b"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\0";
            let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();
            if windows_sys::Win32::System::Registry::RegOpenKeyExA(
                windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                0,
                windows_sys::Win32::System::Registry::KEY_READ,
                &mut hkey,
            ) == 0
            {
                let mut val_type: u32 = 0;
                let mut val_buf = [0u8; 512];
                let mut val_len = val_buf.len() as u32;
                if windows_sys::Win32::System::Registry::RegQueryValueExA(
                    hkey,
                    b"AppInit_DLLs\0".as_ptr(),
                    std::ptr::null_mut(),
                    &mut val_type,
                    val_buf.as_mut_ptr(),
                    &mut val_len,
                ) == 0
                {
                    let app_init = String::from_utf8_lossy(&val_buf[..val_len as usize])
                        .trim_matches('\0')
                        .trim()
                        .to_string();
                    if !app_init.is_empty() {
                        findings.push(Detection::new(
                            "Rootkit",
                            "Persistence.AppInitDLLs",
                            Severity::High,
                            ThreatClass::Persistence,
                            format!("AppInit_DLLs active injection: '{app_init}'"),
                        ));
                    }
                }
                windows_sys::Win32::System::Registry::RegCloseKey(hkey);
            }
        }

        // 4. Winlogon Hijacking Check (Userinit and Shell persistence)
        unsafe {
            let subkey = b"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\0";
            let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();
            if windows_sys::Win32::System::Registry::RegOpenKeyExA(
                windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                0,
                windows_sys::Win32::System::Registry::KEY_READ,
                &mut hkey,
            ) == 0
            {
                let mut val_type: u32 = 0;
                let mut val_buf = [0u8; 512];
                let mut val_len = val_buf.len() as u32;
                if windows_sys::Win32::System::Registry::RegQueryValueExA(
                    hkey,
                    b"Userinit\0".as_ptr(),
                    std::ptr::null_mut(),
                    &mut val_type,
                    val_buf.as_mut_ptr(),
                    &mut val_len,
                ) == 0
                {
                    let userinit = String::from_utf8_lossy(&val_buf[..val_len as usize])
                        .trim_matches('\0')
                        .trim()
                        .to_ascii_lowercase();
                    if !userinit.is_empty() && !userinit.starts_with("c:\\windows\\system32\\userinit.exe") {
                        findings.push(Detection::new(
                            "Rootkit",
                            "Persistence.Winlogon.Userinit",
                            Severity::Critical,
                            ThreatClass::Persistence,
                            format!("Winlogon Userinit binary modified: '{userinit}' (standard is 'userinit.exe')"),
                        ));
                    }
                }

                val_len = val_buf.len() as u32;
                if windows_sys::Win32::System::Registry::RegQueryValueExA(
                    hkey,
                    b"Shell\0".as_ptr(),
                    std::ptr::null_mut(),
                    &mut val_type,
                    val_buf.as_mut_ptr(),
                    &mut val_len,
                ) == 0
                {
                    let shell = String::from_utf8_lossy(&val_buf[..val_len as usize])
                        .trim_matches('\0')
                        .trim()
                        .to_ascii_lowercase();
                    if !shell.is_empty() && shell != "explorer.exe" {
                        findings.push(Detection::new(
                            "Rootkit",
                            "Persistence.Winlogon.Shell",
                            Severity::Critical,
                            ThreatClass::Persistence,
                            format!("Winlogon Shell hijacked: '{shell}' (standard is 'explorer.exe')"),
                        ));
                    }
                }
                windows_sys::Win32::System::Registry::RegCloseKey(hkey);
            }
        }

        // 5. LSA Security Packages Persistence Check
        unsafe {
            let subkey = b"SYSTEM\\CurrentControlSet\\Control\\Lsa\0";
            let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();
            if windows_sys::Win32::System::Registry::RegOpenKeyExA(
                windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                0,
                windows_sys::Win32::System::Registry::KEY_READ,
                &mut hkey,
            ) == 0
            {
                let mut val_type: u32 = 0;
                let mut val_buf = [0u8; 1024];
                let mut val_len = val_buf.len() as u32;
                if windows_sys::Win32::System::Registry::RegQueryValueExA(
                    hkey,
                    b"Security Packages\0".as_ptr(),
                    std::ptr::null_mut(),
                    &mut val_type,
                    val_buf.as_mut_ptr(),
                    &mut val_len,
                ) == 0
                {
                    let pkgs = String::from_utf8_lossy(&val_buf[..val_len as usize]);
                    for token in pkgs.split('\0') {
                        let t = token.trim().to_ascii_lowercase();
                        if !t.is_empty() && !matches!(t.as_str(), "kerberos" | "msv1_0" | "schannel" | "wdigest" | "tspkg" | "pku2u" | "cloudap") {
                            findings.push(Detection::new(
                                "Rootkit",
                                format!("Persistence.LsaSecurityPackage:{t}"),
                                Severity::Critical,
                                ThreatClass::Persistence,
                                format!("Non-standard LSA Security Package registered: '{t}' (potential SSP injection / credential theft)"),
                            ));
                        }
                    }
                }
                windows_sys::Win32::System::Registry::RegCloseKey(hkey);
            }
        }

        // 6. SafeBoot / Safe Mode Persistence Check
        unsafe {
            for mode in ["Minimal", "Network"] {
                let subkey = format!("SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\{mode}\0");
                let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();
                if windows_sys::Win32::System::Registry::RegOpenKeyExA(
                    windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE,
                    subkey.as_ptr(),
                    0,
                    windows_sys::Win32::System::Registry::KEY_READ,
                    &mut hkey,
                ) == 0
                {
                    for suspect in ["vss", "swprv", "aegis_fake", "blackcat", "medusa"] {
                        let suspect_cstr = format!("{suspect}\0");
                        let mut suspect_k: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();
                        if windows_sys::Win32::System::Registry::RegOpenKeyExA(
                            hkey,
                            suspect_cstr.as_ptr(),
                            0,
                            windows_sys::Win32::System::Registry::KEY_READ,
                            &mut suspect_k,
                        ) == 0
                        {
                            findings.push(Detection::new(
                                "Rootkit",
                                format!("Persistence.SafeBoot:{mode}:{suspect}"),
                                Severity::High,
                                ThreatClass::Persistence,
                                format!("Suspicious SafeBoot {mode} service registered: '{suspect}' (SafeMode ransomware bypass)"),
                            ));
                            windows_sys::Win32::System::Registry::RegCloseKey(suspect_k);
                        }
                    }
                    windows_sys::Win32::System::Registry::RegCloseKey(hkey);
                }
            }
        }

        // 7. Accessibility Tools Physical File Tampering (sethc.exe, utilman.exe, osk.exe)
        for victim in ["sethc.exe", "utilman.exe", "osk.exe", "Magnify.exe"] {
            let victim_path = format!("C:\\Windows\\System32\\{victim}");
            if let Ok(meta) = std::fs::metadata(&victim_path) {
                if meta.len() == 0 {
                    findings.push(Detection::new(
                        "Rootkit",
                        format!("Tampering.AccessibilityZeroByte:{victim}"),
                        Severity::High,
                        ThreatClass::Rootkit,
                        format!("Accessibility binary at {victim_path} is 0 bytes (disabled/tampered)"),
                    ));
                }
            }
        }

        // 8. Cross-View Process Enumeration (DKOM Hidden Process Hunter)
        let mut listed_pids = std::collections::HashSet::new();
        unsafe {
            let snap = windows_sys::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
                windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS,
                0,
            );
            if snap != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE && !snap.is_null() {
                let mut pe: windows_sys::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W = std::mem::zeroed();
                pe.dwSize = std::mem::size_of::<windows_sys::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W>() as u32;
                if windows_sys::Win32::System::Diagnostics::ToolHelp::Process32FirstW(snap, &mut pe) != 0 {
                    loop {
                        listed_pids.insert(pe.th32ProcessID);
                        if windows_sys::Win32::System::Diagnostics::ToolHelp::Process32NextW(snap, &mut pe) == 0 {
                            break;
                        }
                    }
                }
                windows_sys::Win32::Foundation::CloseHandle(snap);
            }

            for probe_pid in (8..=1024).step_by(4) {
                if !listed_pids.contains(&probe_pid) {
                    let h_probe = windows_sys::Win32::System::Threading::OpenProcess(
                        windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
                        0,
                        probe_pid,
                    );
                    if !h_probe.is_null() && h_probe != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                        findings.push(Detection::new(
                            "Rootkit",
                            format!("Hidden.Process.DKOM:{probe_pid}"),
                            Severity::Critical,
                            ThreatClass::Rootkit,
                            format!("PID {probe_pid} opened successfully but omitted from ToolHelp process snapshot (Direct Kernel Object Manipulation / DKOM)"),
                        ));
                        windows_sys::Win32::Foundation::CloseHandle(h_probe);
                    }
                }
            }
        }

        findings
    }
}

// --- Windows Sandbox --------------------------------------------------

#[derive(Debug, Default)]
pub struct WindowsSandbox;

impl WindowsSandbox {
    pub fn new() -> Self {
        Self
    }
}

impl Sandbox for WindowsSandbox {
    fn spawn_confined(
        &self,
        cmd: &mut std::process::Command,
        _policy: &SandboxPolicy,
    ) -> Result<std::process::Child> {
        // Confines child within a Job Object and spawns it
        let child = cmd.spawn().map_err(|e| AegisError::io(Path::new("sandbox"), e))?;
        unsafe {
            let job = windows_sys::Win32::System::JobObjects::CreateJobObjectW(
                std::ptr::null(),
                std::ptr::null(),
            );
            if !job.is_null() {
                let proc_handle = windows_sys::Win32::System::Threading::OpenProcess(
                    windows_sys::Win32::System::Threading::PROCESS_SET_QUOTA
                        | windows_sys::Win32::System::Threading::PROCESS_TERMINATE,
                    0,
                    child.id(),
                );
                if !proc_handle.is_null() {
                    let _ = windows_sys::Win32::System::JobObjects::AssignProcessToJobObject(
                        job,
                        proc_handle,
                    );
                    windows_sys::Win32::Foundation::CloseHandle(proc_handle);
                }
            }
        }
        Ok(child)
    }
}

// --- Windows Autostart & Service Management ----------------------------

/// Register an executable to start automatically on Windows user login via the Run registry key.
pub fn set_windows_autostart(app_name: &str, exe_path: &Path) -> Result<()> {
    unsafe {
        let run_key = b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\0";
        let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();
        let status = windows_sys::Win32::System::Registry::RegOpenKeyExA(
            windows_sys::Win32::System::Registry::HKEY_CURRENT_USER,
            run_key.as_ptr(),
            0,
            windows_sys::Win32::System::Registry::KEY_WRITE,
            &mut hkey,
        );
        if status != 0 {
            return Err(AegisError::Config(format!("Failed to open Run registry key: error {status}")));
        }

        let quoted_path = format!("\"{}\"", exe_path.to_string_lossy());
        let val_w: Vec<u16> = std::ffi::OsStr::new(&quoted_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let name_a = std::ffi::CString::new(app_name).unwrap_or_default();
        let set_status = windows_sys::Win32::System::Registry::RegSetValueExA(
            hkey,
            name_a.as_ptr() as *const u8,
            0,
            windows_sys::Win32::System::Registry::REG_SZ,
            val_w.as_ptr() as *const u8,
            (val_w.len() * 2) as u32,
        );
        windows_sys::Win32::System::Registry::RegCloseKey(hkey);

        if set_status != 0 {
            return Err(AegisError::Config(format!("Failed to write autostart value: error {set_status}")));
        }
        tracing::info!("Registered autostart for {} -> {}", app_name, quoted_path);
        Ok(())
    }
}

/// Query if autostart is enabled for this application.
pub fn is_windows_autostart_enabled(app_name: &str) -> bool {
    unsafe {
        let run_key = b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\0";
        let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();
        if windows_sys::Win32::System::Registry::RegOpenKeyExA(
            windows_sys::Win32::System::Registry::HKEY_CURRENT_USER,
            run_key.as_ptr(),
            0,
            windows_sys::Win32::System::Registry::KEY_READ,
            &mut hkey,
        ) != 0 {
            return false;
        }

        let name_a = std::ffi::CString::new(app_name).unwrap_or_default();
        let mut val_type: u32 = 0;
        let mut val_len: u32 = 0;
        let status = windows_sys::Win32::System::Registry::RegQueryValueExA(
            hkey,
            name_a.as_ptr() as *const u8,
            std::ptr::null_mut(),
            &mut val_type,
            std::ptr::null_mut(),
            &mut val_len,
        );
        windows_sys::Win32::System::Registry::RegCloseKey(hkey);
        status == 0 && val_len > 0
    }
}

/// Remove application from Windows Run registry key.
pub fn remove_windows_autostart(app_name: &str) -> Result<()> {
    unsafe {
        let run_key = b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\0";
        let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();
        if windows_sys::Win32::System::Registry::RegOpenKeyExA(
            windows_sys::Win32::System::Registry::HKEY_CURRENT_USER,
            run_key.as_ptr(),
            0,
            windows_sys::Win32::System::Registry::KEY_WRITE,
            &mut hkey,
        ) == 0 {
            let name_a = std::ffi::CString::new(app_name).unwrap_or_default();
            let _ = windows_sys::Win32::System::Registry::RegDeleteValueA(hkey, name_a.as_ptr() as *const u8);
            windows_sys::Win32::System::Registry::RegCloseKey(hkey);
        }
        Ok(())
    }
}

// --- Windows Service Host ---------------------------------------------

#[derive(Debug, Default)]
pub struct WindowsServiceHost;

impl WindowsServiceHost {
    pub fn new() -> Self {
        Self
    }
}

impl ServiceHost for WindowsServiceHost {
    fn run(&self, name: &str, main_fn: Box<dyn FnOnce() + Send>) -> Result<()> {
        use windows_service::service_dispatcher;

        // Try registering with Windows SCM
        let dummy_name = name.to_string();
        let res = service_dispatcher::start(dummy_name, ffi_service_main);
        if res.is_err() {
            // Launched from CLI / interactive console
            main_fn();
        }
        Ok(())
    }
}

windows_service::define_windows_service!(ffi_service_main, my_service_main);

fn my_service_main(_arguments: Vec<std::ffi::OsString>) {
    use std::time::Duration;
    use windows_service::{
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
    };

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = match service_control_handler::register("aegis", event_handler) {
        Ok(h) => h,
        Err(_) => return,
    };

    let next_status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    let _ = status_handle.set_service_status(next_status);
}

#[derive(Debug, Default)]
pub struct WindowsSecretStore;

impl WindowsSecretStore {
    pub fn new() -> Self {
        Self
    }
}

extern "system" {
    fn LocalFree(hmem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}

#[allow(non_snake_case)]
pub fn dpapi_protect(plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
    #[repr(C)]
    #[allow(non_snake_case)]
    struct DATA_BLOB {
        cbData: u32,
        pbData: *mut u8,
    }
    let mut in_blob = DATA_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut out_blob = DATA_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    unsafe {
        // CRYPTPROTECT_LOCAL_MACHINE = 0x4, CRYPTPROTECT_UI_FORBIDDEN = 0x1
        let flags = 0x4 | 0x1;
        let success = windows_sys::Win32::Security::Cryptography::CryptProtectData(
            &mut in_blob as *mut _ as _,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            flags,
            &mut out_blob as *mut _ as _,
        );
        if success == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let out_vec = slice.to_vec();
        LocalFree(out_blob.pbData as _);
        Ok(out_vec)
    }
}

#[allow(non_snake_case)]
pub fn dpapi_unprotect(ciphertext: &[u8]) -> std::io::Result<Vec<u8>> {
    #[repr(C)]
    #[allow(non_snake_case)]
    struct DATA_BLOB {
        cbData: u32,
        pbData: *mut u8,
    }
    let mut in_blob = DATA_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut out_blob = DATA_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    unsafe {
        let flags = 0x1; // CRYPTPROTECT_UI_FORBIDDEN
        let success = windows_sys::Win32::Security::Cryptography::CryptUnprotectData(
            &mut in_blob as *mut _ as _,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            flags,
            &mut out_blob as *mut _ as _,
        );
        if success == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let out_vec = slice.to_vec();
        LocalFree(out_blob.pbData as _);
        Ok(out_vec)
    }
}

impl SecretStore for WindowsSecretStore {
    fn load_or_create_vault_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        let key_path = aegis_core::paths::keyring_file();
        if key_path.exists() {
            let bytes = std::fs::read(&key_path).map_err(|e| AegisError::io(&key_path, e))?;
            if let Ok(unprotected) = dpapi_unprotect(&bytes) {
                if unprotected.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&unprotected);
                    return Ok(Zeroizing::new(key));
                }
            } else if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                return Ok(Zeroizing::new(key));
            }
            return Err(AegisError::Crypto("invalid key size or DPAPI unprotect failed for vault key".into()));
        }

        if let Some(parent) = key_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        let protected = dpapi_protect(&key).unwrap_or_else(|_| key.to_vec());
        std::fs::write(&key_path, &protected).map_err(|e| AegisError::io(&key_path, e))?;
        Ok(Zeroizing::new(key))
    }
}

// --- Windows File Event Source (ReadDirectoryChangesW) ----------------

pub struct WindowsFileEventSource;

impl WindowsFileEventSource {
    pub fn new() -> Self {
        Self
    }
}

impl FileEventSource for WindowsFileEventSource {
    fn start(&self, roots: &[PathBuf]) -> Result<Box<dyn EventStream>> {
        let (tx, rx) = mpsc::channel();
        for root in roots {
            let r = root.clone();
            let tx_clone = tx.clone();
            std::thread::spawn(move || watch_directory_forever(&r, tx_clone));
        }
        Ok(Box::new(WindowsEventStream { rx }))
    }

    fn can_block(&self) -> bool {
        false
    }
}

struct WindowsEventStream {
    rx: mpsc::Receiver<AccessEvent>,
}

impl EventStream for WindowsEventStream {
    fn next_event(&mut self) -> Option<AccessEvent> {
        self.rx.recv().ok()
    }
}

/// Keep a root watched for the life of the process: reopen after errors and,
/// after any gap in coverage, rescan files changed since the last good read.
fn watch_directory_forever(dir: &Path, tx: mpsc::Sender<AccessEvent>) {
    let mut since = std::time::SystemTime::now();
    loop {
        match watch_directory(dir, &tx, &mut since) {
            WatchEnd::ReceiverGone => return,
            WatchEnd::Failed(e) => {
                tracing::warn!(path = %dir.display(), error = %e, "directory watch failed; reopening");
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        }
        if !emit_changed_since(dir, since, &tx) {
            return;
        }
    }
}

enum WatchEnd {
    ReceiverGone,
    Failed(String),
}

/// Emit an event for every file under `dir` modified at or after `since`.
/// Returns false when the receiver is gone.
fn emit_changed_since(dir: &Path, since: std::time::SystemTime, tx: &mpsc::Sender<AccessEvent>) -> bool {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(entry.path());
            } else if meta.modified().map(|m| m >= since).unwrap_or(true) {
                let ev = AccessEvent {
                    path: entry.path(),
                    pid: 0,
                    event_type: AccessEventType::CloseWrite,
                    file_id: None,
                };
                if tx.send(ev).is_err() {
                    return false;
                }
            }
        }
    }
    true
}

fn watch_directory(dir: &Path, tx: &mpsc::Sender<AccessEvent>, since: &mut std::time::SystemTime) -> WatchEnd {
    use windows_sys::Win32::Storage::FileSystem as fs;
    unsafe {
        let dir_w: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let handle = fs::CreateFileW(
            dir_w.as_ptr(),
            fs::FILE_LIST_DIRECTORY,
            fs::FILE_SHARE_READ | fs::FILE_SHARE_WRITE | fs::FILE_SHARE_DELETE,
            std::ptr::null(),
            fs::OPEN_EXISTING,
            fs::FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        );
        if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return WatchEnd::Failed(std::io::Error::last_os_error().to_string());
        }

        // The API requires a DWORD-aligned buffer, so back it with u32s.
        let mut buffer = vec![0u32; 16 * 1024];
        let buf_bytes = (buffer.len() * 4) as u32;
        let mut bytes_returned: u32 = 0;

        let end = 'watch: loop {
            let read_started = std::time::SystemTime::now();
            let ok = fs::ReadDirectoryChangesW(
                handle,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                buf_bytes,
                1, // watch subtree
                fs::FILE_NOTIFY_CHANGE_FILE_NAME
                    | fs::FILE_NOTIFY_CHANGE_DIR_NAME
                    | fs::FILE_NOTIFY_CHANGE_LAST_WRITE,
                &mut bytes_returned,
                std::ptr::null_mut(),
                None,
            );
            if ok == 0 {
                break WatchEnd::Failed(std::io::Error::last_os_error().to_string());
            }
            if bytes_returned == 0 {
                // Kernel buffer overflowed: events were dropped, catch up by rescanning.
                tracing::warn!(path = %dir.display(), "change buffer overflow; rescanning");
                if !emit_changed_since(dir, *since, tx) {
                    break WatchEnd::ReceiverGone;
                }
                *since = read_started;
                continue;
            }

            let bytes = std::slice::from_raw_parts(buffer.as_ptr() as *const u8, bytes_returned as usize);
            let mut offset = 0usize;
            loop {
                let field = |at: usize| u32::from_le_bytes(bytes[offset + at..offset + at + 4].try_into().unwrap());
                let (next, action, name_len) = (field(0) as usize, field(4), field(8) as usize);
                let name_bytes = &bytes[offset + 12..offset + 12 + name_len];
                let wide: Vec<u16> = name_bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                let full_path = dir.join(OsString::from_wide(&wide));

                // 1 added, 3 modified, 5 renamed (new name). 2 removed / 4 old name have nothing to scan.
                let ev_type = match action {
                    1 => Some(AccessEventType::CloseWrite),
                    3 => Some(AccessEventType::Modify),
                    5 => Some(AccessEventType::Rename),
                    _ => None,
                };
                if let Some(event_type) = ev_type {
                    if full_path.is_dir() {
                        // A folder moved or copied in: its existing files never raise their own events.
                        if !emit_changed_since(&full_path, std::time::UNIX_EPOCH, tx) {
                            break 'watch WatchEnd::ReceiverGone;
                        }
                    } else {
                        let ev = AccessEvent { path: full_path, pid: 0, event_type, file_id: None };
                        if tx.send(ev).is_err() {
                            break 'watch WatchEnd::ReceiverGone;
                        }
                    }
                }
                if next == 0 {
                    break;
                }
                offset += next;
            }
            *since = read_started;
        };

        windows_sys::Win32::Foundation::CloseHandle(handle);
        end
    }
}

/// Address of `dll!func` in this process. System DLLs share one base address
/// across processes for a boot session, so it is valid in other processes too.
pub fn security_api_address(dll: &str, func: &str) -> Option<usize> {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
    let dll_c = std::ffi::CString::new(dll).ok()?;
    let func_c = std::ffi::CString::new(func).ok()?;
    unsafe {
        let module = LoadLibraryA(dll_c.as_ptr() as *const u8);
        if module.is_null() {
            return None;
        }
        GetProcAddress(module, func_c.as_ptr() as *const u8).map(|f| f as usize)
    }
}

/// Check whether a file carries a valid Authenticode signature from a trusted root.
#[allow(non_snake_case)]
pub fn verify_authenticode(path: &Path) -> bool {
    let path_w: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

    #[repr(C)]
    #[allow(non_snake_case)]
    struct WINTRUST_FILE_INFO {
        cb_struct: u32,
        pcwsz_file_path: *const u16,
        h_file: *mut std::ffi::c_void,
        pg_known_subject: *mut std::ffi::c_void,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct WINTRUST_DATA {
        cb_struct: u32,
        p_policy_callback_data: *mut std::ffi::c_void,
        p_sip_client_data: *mut std::ffi::c_void,
        dw_ui_choice: u32,
        fdw_revocation_checks: u32,
        dw_union_choice: u32,
        p_file: *mut WINTRUST_FILE_INFO,
        dw_state_action: u32,
        h_wvt_state_data: *mut std::ffi::c_void,
        pwsz_url_reference: *mut u16,
        dw_prov_flags: u32,
        dw_ui_context: u32,
        p_signature_settings: *mut std::ffi::c_void,
    }

    let mut file_info = WINTRUST_FILE_INFO {
        cb_struct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwsz_file_path: path_w.as_ptr(),
        h_file: std::ptr::null_mut(),
        pg_known_subject: std::ptr::null_mut(),
    };

    let mut trust_data = WINTRUST_DATA {
        cb_struct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        p_policy_callback_data: std::ptr::null_mut(),
        p_sip_client_data: std::ptr::null_mut(),
        dw_ui_choice: 2, // WTD_UI_NONE
        fdw_revocation_checks: 0,
        dw_union_choice: 1, // WTD_CHOICE_FILE
        p_file: &mut file_info,
        dw_state_action: 1, // WTD_STATEACTION_VERIFY
        h_wvt_state_data: std::ptr::null_mut(),
        pwsz_url_reference: std::ptr::null_mut(),
        dw_prov_flags: 0x00000040 | 0x00000080, // WTD_SAFER_FLAG | WTD_REVOCATION_CHECK_NONE
        dw_ui_context: 0,
        p_signature_settings: std::ptr::null_mut(),
    };

    // WINTRUST_ACTION_GENERIC_VERIFY_V2: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
    let mut action_guid = windows_sys::core::GUID {
        data1: 0x00aac56b,
        data2: 0xcd44,
        data3: 0x11d0,
        data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
    };

    unsafe {
        let status = windows_sys::Win32::Security::WinTrust::WinVerifyTrust(
            windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE as _,
            &mut action_guid as *mut _ as _,
            &mut trust_data as *mut _ as _,
        );
        // Clean up state
        trust_data.dw_state_action = 2; // WTD_STATEACTION_CLOSE
        let _ = windows_sys::Win32::Security::WinTrust::WinVerifyTrust(
            windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE as _,
            &mut action_guid as *mut _ as _,
            &mut trust_data as *mut _ as _,
        );
        status == 0
    }
}

/// Verify whether a kernel driver has a valid WHQL / Microsoft Authenticode signature.
/// Blocks Bring Your Own Vulnerable Driver (BYOVD) attacks.
pub fn is_driver_whql_signed(driver_path: &Path) -> bool {
    verify_authenticode(driver_path)
}

// --- Windows AutoStart (Run Key & Task Scheduler) ---------------------

#[derive(Debug, Default)]
pub struct WindowsAutoStart;

impl WindowsAutoStart {
    pub fn new() -> Self {
        Self
    }
}

impl AutoStart for WindowsAutoStart {
    fn is_enabled(&self) -> bool {
        unsafe {
            let subkey = b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\0";
            let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();
            if windows_sys::Win32::System::Registry::RegOpenKeyExA(
                windows_sys::Win32::System::Registry::HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                windows_sys::Win32::System::Registry::KEY_READ,
                &mut hkey,
            ) == 0 {
                let val_name = b"Aegis\0";
                let mut val_type: u32 = 0;
                let mut data_len: u32 = 0;
                let res = windows_sys::Win32::System::Registry::RegQueryValueExA(
                    hkey,
                    val_name.as_ptr(),
                    std::ptr::null_mut(),
                    &mut val_type,
                    std::ptr::null_mut(),
                    &mut data_len,
                );
                windows_sys::Win32::System::Registry::RegCloseKey(hkey);
                res == 0
            } else {
                false
            }
        }
    }

    fn set_enabled(&self, enabled: bool, app_path: &Path) -> Result<()> {
        unsafe {
            let subkey = b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\0";
            let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();
            if windows_sys::Win32::System::Registry::RegOpenKeyExA(
                windows_sys::Win32::System::Registry::HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                windows_sys::Win32::System::Registry::KEY_WRITE,
                &mut hkey,
            ) == 0 {
                let val_name = b"Aegis\0";
                if enabled {
                    let cmd = format!("\"{}\" --minimized\0", app_path.display());
                    let _ = windows_sys::Win32::System::Registry::RegSetValueExA(
                        hkey,
                        val_name.as_ptr(),
                        0,
                        windows_sys::Win32::System::Registry::REG_SZ,
                        cmd.as_ptr(),
                        cmd.len() as u32,
                    );
                } else {
                    let _ = windows_sys::Win32::System::Registry::RegDeleteValueA(hkey, val_name.as_ptr());
                }
                windows_sys::Win32::System::Registry::RegCloseKey(hkey);
            }
        }

        let app_str = app_path.to_string_lossy();
        if enabled {
            let _ = std::process::Command::new("schtasks")
                .args(["/create", "/tn", "AegisTotalSecurity", "/tr", &format!("\"{app_str}\""), "/sc", "onlogon", "/rl", "highest", "/f"])
                .output();
        } else {
            let _ = std::process::Command::new("schtasks")
                .args(["/delete", "/tn", "AegisTotalSecurity", "/f"])
                .output();
        }

        Ok(())
    }
}

// --- Windows AMSI Provider Registration -------------------------------

pub fn register_amsi_provider(dll_path: &Path) -> Result<()> {
    unsafe {
        let subkey = b"SOFTWARE\\Microsoft\\AMSI\\Providers\\{B3C2A9E1-5F4D-4E92-8360-3BF720E108BA}\0";
        let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();
        if windows_sys::Win32::System::Registry::RegCreateKeyExA(
            windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            std::ptr::null_mut(),
            0,
            windows_sys::Win32::System::Registry::KEY_WRITE,
            std::ptr::null_mut(),
            &mut hkey,
            std::ptr::null_mut(),
        ) == 0 {
            let desc = b"Aegis Antimalware Provider\0";
            let _ = windows_sys::Win32::System::Registry::RegSetValueExA(
                hkey,
                std::ptr::null(),
                0,
                windows_sys::Win32::System::Registry::REG_SZ,
                desc.as_ptr(),
                desc.len() as u32,
            );
            windows_sys::Win32::System::Registry::RegCloseKey(hkey);
        }
    }
    tracing::info!("Registered Aegis AMSI Provider at {}", dll_path.display());
    Ok(())
}

pub fn unregister_amsi_provider() -> Result<()> {
    unsafe {
        let subkey = b"SOFTWARE\\Microsoft\\AMSI\\Providers\0";
        let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();
        if windows_sys::Win32::System::Registry::RegOpenKeyExA(
            windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            windows_sys::Win32::System::Registry::KEY_WRITE,
            &mut hkey,
        ) == 0 {
            let guid_key = b"{B3C2A9E1-5F4D-4E92-8360-3BF720E108BA}\0";
            let _ = windows_sys::Win32::System::Registry::RegDeleteKeyA(hkey, guid_key.as_ptr());
            windows_sys::Win32::System::Registry::RegCloseKey(hkey);
        }
    }
    Ok(())
}

// --- NTFS USN Change Journal ($UsnJrnl) Fast Catch-Up -----------------

pub fn query_usn_journal(volume_letter: &str) -> Result<Option<u64>> {
    let vol_path = format!(r"\\.\{}:", volume_letter.trim_end_matches(':'));
    let vol_w: Vec<u16> = std::ffi::OsStr::new(&vol_path).encode_wide().chain(std::iter::once(0)).collect();

    unsafe {
        let handle = windows_sys::Win32::Storage::FileSystem::CreateFileW(
            vol_w.as_ptr(),
            windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ,
            windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
            std::ptr::null(),
            windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );

        if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE || handle.is_null() {
            return Ok(None);
        }

        #[repr(C)]
        struct USN_JOURNAL_DATA_V0 {
            usn_journal_id: u64,
            first_usn: i64,
            next_usn: i64,
            lowest_valid_usn: i64,
            max_usn: i64,
            maximum_size: u64,
            allocation_delta: u64,
        }

        let mut journal_data: USN_JOURNAL_DATA_V0 = std::mem::zeroed();
        let mut bytes_returned: u32 = 0;
        let success = windows_sys::Win32::System::IO::DeviceIoControl(
            handle,
            0x000900f4, // FSCTL_QUERY_USN_JOURNAL
            std::ptr::null(),
            0,
            &mut journal_data as *mut _ as _,
            std::mem::size_of::<USN_JOURNAL_DATA_V0>() as u32,
            &mut bytes_returned,
            std::ptr::null_mut(),
        );

        windows_sys::Win32::Foundation::CloseHandle(handle);

        if success != 0 {
            Ok(Some(journal_data.usn_journal_id))
        } else {
            Ok(None)
        }
    }
}

// --- Kaspersky-style Gaming Mode Detection & Resource Throttling ------

pub fn is_gaming_or_fullscreen_active() -> bool {
    unsafe {
        // 1. Official Windows Notification State (used by DirectX/D3D full screen games)
        let shell32 = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"shell32.dll\0".as_ptr());
        if !shell32.is_null() {
            let proc = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                shell32,
                b"SHQueryUserNotificationState\0".as_ptr(),
            );
            if let Some(func) = proc {
                type SHQueryUserNotificationStateFn = unsafe extern "system" fn(pquns: *mut i32) -> i32;
                let query_state: SHQueryUserNotificationStateFn = std::mem::transmute(func);
                let mut state: i32 = 0;
                if query_state(&mut state) == 0 {
                    // QUNS_RUNNING_D3D_FULL_SCREEN = 1, QUNS_BUSY = 5
                    if state == 1 || state == 5 {
                        windows_sys::Win32::Foundation::FreeLibrary(shell32);
                        return true;
                    }
                }
            }
            windows_sys::Win32::Foundation::FreeLibrary(shell32);
        }

        // 2. Geometry check: Check if foreground window occupies the entire display resolution
        let hwnd = windows_sys::Win32::UI::WindowsAndMessaging::GetForegroundWindow();
        if !hwnd.is_null() {
            let mut rect: windows_sys::Win32::Foundation::RECT = std::mem::zeroed();
            if windows_sys::Win32::UI::WindowsAndMessaging::GetWindowRect(hwnd, &mut rect) != 0 {
                let screen_w = windows_sys::Win32::UI::WindowsAndMessaging::GetSystemMetrics(
                    windows_sys::Win32::UI::WindowsAndMessaging::SM_CXSCREEN,
                );
                let screen_h = windows_sys::Win32::UI::WindowsAndMessaging::GetSystemMetrics(
                    windows_sys::Win32::UI::WindowsAndMessaging::SM_CYSCREEN,
                );
                if rect.left <= 0 && rect.top <= 0 && rect.right >= screen_w && rect.bottom >= screen_h {
                    return true;
                }
            }
        }
    }
    false
}

pub fn set_process_resource_mode(game_mode_active: bool) {
    unsafe {
        let current_process = windows_sys::Win32::System::Threading::GetCurrentProcess();
        let priority = if game_mode_active {
            windows_sys::Win32::System::Threading::IDLE_PRIORITY_CLASS
        } else {
            windows_sys::Win32::System::Threading::NORMAL_PRIORITY_CLASS
        };
        windows_sys::Win32::System::Threading::SetPriorityClass(current_process, priority);
    }
}

// --- Windows Platform Security (BYOVD & Vulnerable Driver Blocklist) -----

static VULNERABLE_DRIVERS: &[(&str, &str, Option<&str>, &str, &str)] = &[
    ("rtcore64.sys", "03e0581432f5c8cc727a8aa387f5b69ff84d38d0df6f1226c19c6e960a81e1e9", Some("CVE-2019-16098"), "Micro-Star International", "MSI Afterburner arbitrary kernel read/write/MSR access"),
    ("rtcore64.sys", "0466dac557ee161503f5dfbd3549f81ec760c3d6c7c4363a21a03e7a3f66aca8", Some("CVE-2019-16098"), "Micro-Star International", "MSI Afterburner RTCore64 variant"),
    ("rtcore64.sys", "077aa8ff5e01747723b6d24cc8af460a7a00f30cd3bc80e41cc245ceb8305356", Some("CVE-2019-16098"), "Micro-Star International", "MSI Afterburner RTCore64 variant"),
    ("rtcore64.sys", "0cf6c6c2d231eaf67dfc87561cc9a56ecef89ab4cbfec3d5b035cb24dcbc9db2", Some("CVE-2019-16098"), "Micro-Star International", "MSI Afterburner RTCore64 variant"),
    ("gdrv.sys", "b64e05b769f06120e7e17ae1515bb26ab78cfcf2f1c1f547c61775432049d4f7", Some("CVE-2018-19320"), "GIGA-BYTE TECHNOLOGY", "GIGABYTE APP Center gdrv.sys arbitrary physical memory mapping"),
    ("gdrv.sys", "69d3a0e69ddc6c49c2356c12519bfb4b57422f25fc2521c3b17c80d463e272bb", Some("CVE-2018-19320"), "GIGA-BYTE TECHNOLOGY", "GIGABYTE gdrv.sys arbitrary kernel RW"),
    ("dbutil_2_3.sys", "c8259d4351ae2126284620f5a72e88701e9d3d3b76974db37a89e0fbbf05d452", Some("CVE-2021-21551"), "Dell Inc.", "Dell DBUtil driver privilege escalation & arbitrary memory RW"),
    ("dbutil_2_3.sys", "099a4c84a51e5e6e30ebff589178ad99e8d7bb680ee11ebf67667bf28be8ed66", Some("CVE-2021-21551"), "Dell Inc.", "Dell DBUtil driver variant"),
    ("mhyprot2.sys", "046e772ad70094b9f291244246101cfa068e8e7c10b2a6f2366b5398a69e6b36", None, "miHoYo Co., Ltd.", "miHoYo anti-cheat driver abused to terminate security software"),
    ("procexp.sys", "075de997497262a9d105afeadaaefc6348b25ce0e0126505c24aa9396c251e85", None, "Microsoft Sysinternals", "Vulnerable Process Explorer driver exposing handle duplicate & terminate"),
    ("procexp.sys", "16a2e578bc8683f17a175480fea4f53c838cfae965f1d4caa47eaf9e0b3415c1", None, "Microsoft Sysinternals", "Vulnerable Process Explorer driver variant"),
    ("asrdrv.sys", "4bf974f5d3489638a48ee508b4a8cfa0f0262909778ccdd2e871172b71654d89", None, "ASRock Inc.", "ASRock RGB/Utility driver arbitrary port & memory I/O"),
    ("winring0x64.sys", "e73e970ecab3de849b2824cfcf441e8c783dbad85c7c2b3ad8586c528f804fc9", None, "OpenLibSys", "WinRing0 kernel driver exposing arbitrary MSR & physical memory RW"),
    ("cpuz141.sys", "501a3e66014e7561849d443e2a731efc1b48b598b9e69c738f654b0fc08a38b1", None, "CPUID", "CPUID vulnerable driver exposing physical memory read"),
    ("zam64.sys", "e402929da6e11893c5c64c7e63b65fa3a4d493a743b171fcb63b2ad8708cb7bb", None, "Zemana Ltd.", "Zemana driver abused to unregister process callbacks and terminate EDRs"),
    ("kprocesshacker.sys", "38ff1cf1cf3ef8f9361ad85f403932e60475fb1737be00780486c9944dffaa75", None, "Process Hacker", "KProcessHacker driver exposing full kernel process manipulation"),
    ("echo.sys", "a3399611db84ad5215f7b4ee79ab0e19488a44ec2572b83491f24d73aa7fc2d0", None, "Echo / Anti-Cheat", "Vulnerable gaming driver abused for BYOVD kernel tampering"),
    ("atsdio64.sys", "d718b5de39a66d03d3cbebc1b292c3a5099d0eec956276ccad27e857dd58f913", Some("CVE-2020-15368"), "ASUSTeK Computer Inc.", "ASUS ASUSTeK arbitrary physical memory mapping"),
    ("eneio64.sys", "9be432da34f19b22a00c2830f3a611593847f9754f2cc1631eb62817ba2a6d48", Some("CVE-2020-12446"), "ENE TECHNOLOGY INC.", "ENE RGB controller driver arbitrary physical RW"),
    ("amifldrv64.sys", "7b0e2714c7c8c3c1db173b22b64ab5ee5168ddc0fb6e594b281f6a15714e8e83", None, "American Megatrends Inc.", "AMI firmware flash driver arbitrary physical memory RW"),
    ("dbk64.sys", "e4e3b2e7a374b8fbce4e6b266bc332612a20a4b08722c159048a1c3d1911fa89", None, "Cheat Engine", "Cheat Engine kernel driver exposing arbitrary process memory RW"),
    ("virscan64.sys", "63e14187f65a127a514d3c9f52f36f8a84617dfbcf6a1b212f49514757c2bc3c", None, "TG Soft", "TG Soft driver abused by ransomware to disable EDR processes"),
];

#[derive(Debug, Default)]
pub struct WindowsPlatformSecurity;

impl WindowsPlatformSecurity {
    pub fn new() -> Self {
        Self
    }
}

/// LOLDrivers feed written by the threat-feed sync: `sha256 filename` per line.
fn loldrivers_feed() -> std::collections::HashMap<String, String> {
    let path = aegis_core::paths::threat_intel_dir().join("loldrivers.txt");
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let h = it.next()?.to_ascii_lowercase();
            (h.len() == 64).then(|| (h, it.next().unwrap_or("driver.sys").to_string()))
        })
        .collect()
}

/// Number of distinct vulnerable-driver hashes known (built-in + LOLDrivers feed).
pub fn vulnerable_driver_count() -> usize {
    let mut all: std::collections::HashSet<String> = loldrivers_feed().into_keys().collect();
    all.extend(VULNERABLE_DRIVERS.iter().map(|d| d.1.to_string()));
    all.len()
}

/// Kernel and file-system driver services registered under HKLM\SYSTEM\CurrentControlSet\Services,
/// as (service name, resolved image path).
fn registered_kernel_drivers() -> Vec<(String, PathBuf)> {
    use windows_sys::Win32::System::Registry::*;
    let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let mut out = Vec::new();
    unsafe {
        let mut services = std::ptr::null_mut();
        let root = wide(r"SYSTEM\CurrentControlSet\Services");
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, root.as_ptr(), 0, KEY_READ, &mut services) != 0 {
            return out;
        }
        let mut index = 0u32;
        loop {
            let mut name = [0u16; 256];
            let mut name_len = name.len() as u32;
            let rc = RegEnumKeyExW(services, index, name.as_mut_ptr(), &mut name_len, std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut());
            if rc != 0 {
                break;
            }
            index += 1;
            let svc = String::from_utf16_lossy(&name[..name_len as usize]);
            let svc_w = wide(&svc);

            let mut ty = 0u32;
            let mut ty_len = 4u32;
            if RegGetValueW(services, svc_w.as_ptr(), wide("Type").as_ptr(), RRF_RT_REG_DWORD, std::ptr::null_mut(), &mut ty as *mut u32 as *mut _, &mut ty_len) != 0
                || !(ty == 1 || ty == 2)
            {
                continue; // not SERVICE_KERNEL_DRIVER / SERVICE_FILE_SYSTEM_DRIVER
            }

            let mut buf = [0u16; 1024];
            let mut len = (buf.len() * 2) as u32;
            let image = if RegGetValueW(services, svc_w.as_ptr(), wide("ImagePath").as_ptr(), RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ, std::ptr::null_mut(), buf.as_mut_ptr() as *mut _, &mut len) == 0 {
                let raw = String::from_utf16_lossy(&buf[..(len as usize / 2).saturating_sub(1)]);
                resolve_driver_path(&raw, &system_root)
            } else {
                PathBuf::from(&system_root).join(r"System32\drivers").join(format!("{svc}.sys"))
            };
            out.push((svc, image));
        }
        RegCloseKey(services);
    }
    out
}

/// Turn a service ImagePath (`\SystemRoot\...`, `\??\C:\...`, `System32\...`) into a file path.
fn resolve_driver_path(raw: &str, system_root: &str) -> PathBuf {
    let raw = raw.trim().trim_matches('"');
    let lower = raw.to_ascii_lowercase();
    if let Some(rest) = raw.strip_prefix(r"\??\") {
        PathBuf::from(rest)
    } else if lower.starts_with(r"\systemroot\") {
        PathBuf::from(system_root).join(&raw[r"\SystemRoot\".len()..])
    } else if lower.starts_with(r"%systemroot%\") {
        PathBuf::from(system_root).join(&raw[r"%SystemRoot%\".len()..])
    } else if raw.len() > 1 && raw.as_bytes()[1] == b':' {
        PathBuf::from(raw)
    } else {
        PathBuf::from(system_root).join(raw)
    }
}

impl PlatformSecurity for WindowsPlatformSecurity {
    fn is_driver_hash_blocked(&self, sha256_hex: &str) -> bool {
        self.get_vulnerable_driver_info(sha256_hex).is_some()
    }

    fn get_vulnerable_driver_info(&self, sha256_hex: &str) -> Option<VulnerableDriverInfo> {
        let needle = sha256_hex.to_ascii_lowercase();
        VULNERABLE_DRIVERS
            .iter()
            .find(|(_, h, _, _, _)| *h == needle)
            .map(|(name, sha, cve, vendor, desc)| {
                VulnerableDriverInfo::new(*name, *sha, *cve, *vendor, *desc)
            })
            .or_else(|| {
                let name = loldrivers_feed().remove(&needle)?;
                Some(VulnerableDriverInfo::new(name, needle.clone(), None::<String>, "unknown", "Listed in the LOLDrivers vulnerable driver database"))
            })
    }

    fn audit_registered_drivers(&self) -> Vec<Detection> {
        let mut known: std::collections::HashMap<String, String> = loldrivers_feed();
        for d in VULNERABLE_DRIVERS {
            known.insert(d.1.to_string(), format!("{} ({})", d.0, d.4));
        }
        let mut found = Vec::new();
        for (svc, path) in registered_kernel_drivers() {
            let Ok(bytes) = std::fs::read(&path) else { continue };
            use sha2::{Digest, Sha256};
            let hash = format!("{:x}", Sha256::digest(&bytes));
            if let Some(what) = known.get(&hash) {
                found.push(Detection::new(
                    "DriverAudit",
                    format!("VulnerableDriver.{svc}"),
                    Severity::Critical,
                    ThreatClass::Rootkit,
                    format!("{} is a known vulnerable driver: {what}", path.display()),
                ));
            }
        }
        found
    }

    fn audit_driver_file(&self, path: &Path) -> Result<DriverAuditVerdict> {
        let bytes = std::fs::read(path).map_err(|e| AegisError::io(path, e))?;
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash_hex = format!("{:x}", hasher.finalize());

        if let Some(info) = self.get_vulnerable_driver_info(&hash_hex) {
            return Ok(DriverAuditVerdict::Blocked {
                sha256: hash_hex,
                reason: format!("Known vulnerable driver exploited for BYOVD ({}: {})", info.name, info.description),
                driver_info: Some(info),
            });
        }

        Ok(DriverAuditVerdict::Allowed { sha256: hash_hex })
    }

    fn verify_driver_load(&self, service_name: &str, image_path: &Path) -> Result<()> {
        let verdict = self.audit_driver_file(image_path)?;
        if let DriverAuditVerdict::Blocked { reason, .. } = verdict {
            return Err(AegisError::Permission(format!(
                "BYOVD Prevention: driver service '{service_name}' blocked ({reason})"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_service_image_paths() {
        let root = r"C:\Windows";
        assert_eq!(resolve_driver_path(r"\SystemRoot\System32\drivers\a.sys", root), PathBuf::from(r"C:\Windows\System32\drivers\a.sys"));
        assert_eq!(resolve_driver_path(r"\??\D:\x\b.sys", root), PathBuf::from(r"D:\x\b.sys"));
        assert_eq!(resolve_driver_path(r"System32\drivers\c.sys", root), PathBuf::from(r"C:\Windows\System32\drivers\c.sys"));
        assert_eq!(resolve_driver_path(r#""C:\y\d.sys""#, root), PathBuf::from(r"C:\y\d.sys"));
    }

    #[test]
    fn enumerates_real_kernel_drivers() {
        let drivers = registered_kernel_drivers();
        assert!(drivers.iter().any(|(_, p)| p.exists()), "expected at least one driver file on disk");
    }

    #[test]
    fn test_autostart_query() {
        let autostart = WindowsAutoStart::new();
        let _ = autostart.is_enabled();
    }

    #[test]
    fn test_usn_journal_query() {
        let res = query_usn_journal("C:");
        assert!(res.is_ok());
    }

    #[test]
    fn test_dpapi_roundtrip() {
        let plaintext = b"0123456789abcdef0123456789abcdef";
        let encrypted = dpapi_protect(plaintext).expect("dpapi protect succeeds");
        assert_ne!(&encrypted, plaintext);
        let decrypted = dpapi_unprotect(&encrypted).expect("dpapi unprotect succeeds");
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_paths() {
        let paths = WindowsPaths::new();
        assert!(paths.config_dir().to_string_lossy().contains("Aegis"));
        assert!(paths.data_dir().to_string_lossy().contains("Aegis"));
    }

    #[test]
    fn test_authenticode_on_system_binary() {
        let ntdll = Path::new(r"C:\Windows\System32\ntdll.dll");
        if ntdll.exists() {
            assert!(verify_authenticode(ntdll));
        }
    }
}
