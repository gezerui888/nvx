use std::ffi::{OsStr, OsString, c_void};
use std::fs::{self, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::time::{Duration, Instant};
use std::{mem, ptr};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER,
    ERROR_IO_PENDING, ERROR_MORE_DATA, ERROR_NO_DATA, ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY,
    ERROR_PIPE_NOT_CONNECTED, ERROR_SHARING_VIOLATION, ERROR_SUCCESS, FILETIME, FreeLibrary,
    GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED, GetFileInformationByHandle, OPEN_EXISTING,
    ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
};
#[cfg(feature = "cli")]
use windows_sys::Win32::Storage::FileSystem::{LockFile, UnlockFile};
#[cfg(feature = "cli")]
use windows_sys::Win32::System::Console::{CTRL_C_EVENT, SetConsoleCtrlHandler};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW};
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW};
#[cfg(feature = "cli")]
use windows_sys::Win32::System::Threading::GetExitCodeProcess;
use windows_sys::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW,
    CREATE_UNICODE_ENVIRONMENT, CreateEventW, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetProcessTimes, INFINITE, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject,
};

use super::Transport;
use crate::hypervisor::Hypervisor;

/// Whether this host can run NVX microVMs.
pub const SUPPORTED: bool = true;

/// Encodes `value` as a NUL-terminated UTF-16 string for Win32.
fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain([0]).collect()
}

/// Returns the calling thread's Win32 last-error code.
fn last_error() -> u32 {
    // SAFETY: GetLastError has no preconditions.
    unsafe { GetLastError() }
}

/// Takes ownership of a newly returned valid Win32 `handle`.
fn owned(handle: HANDLE) -> Option<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        None
    } else {
        // SAFETY: the caller passes a freshly opened handle that nothing else owns.
        Some(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
    }
}

/// Borrows an owned handle in the form expected by `windows-sys`.
fn raw(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle() as HANDLE
}

/// Opens process `pid` with `access`, returning `None` on any Win32 failure.
fn open_handle(pid: u32, access: u32) -> Option<OwnedHandle> {
    // SAFETY: OpenProcess has no memory-safety preconditions.
    owned(unsafe { OpenProcess(access, 0, pid) })
}

/// Returns the process creation `FILETIME`, used with the PID as a stable identity.
fn creation_time(process: &OwnedHandle) -> io::Result<u64> {
    let mut created = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exited = created;
    let mut kernel = created;
    let mut user = created;
    // SAFETY: the handle has query access and every output pointer is valid.
    let succeeded = unsafe {
        GetProcessTimes(
            raw(process),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    } != 0;
    if succeeded {
        Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Polls `process` without waiting and reports whether it has exited.
fn has_exited(process: &OwnedHandle) -> io::Result<bool> {
    // SAFETY: the handle has synchronize access; a zero timeout only polls.
    match unsafe { WaitForSingleObject(raw(process), 0) } {
        WAIT_TIMEOUT => Ok(false),
        WAIT_OBJECT_0 => Ok(true),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Opens a process, returning `None` if it does not exist or belongs to another user.
///
/// OpenVMM always runs as the calling user, so a process that denies access cannot be the
/// sandbox's VM, even if it reuses the recorded process ID.
fn open_existing_process(pid: u32, access: u32) -> io::Result<Option<OwnedHandle>> {
    if let Some(process) = open_handle(pid, access) {
        return Ok(Some(process));
    }
    match last_error() {
        ERROR_INVALID_PARAMETER | ERROR_ACCESS_DENIED => Ok(None),
        error => Err(io::Error::from_raw_os_error(error as i32)),
    }
}

/// Returns the creation time of a live process, `None` if the process no longer exists or
/// belongs to another user, or an error if its state cannot be determined.
pub fn process_start_time(pid: u32) -> io::Result<Option<u64>> {
    let Some(process) =
        open_existing_process(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE)?
    else {
        return Ok(None);
    };
    if has_exited(&process)? {
        return Ok(None);
    }
    creation_time(&process).map(Some)
}

/// A process that this user may query and wait for, and terminate when [`terminate`] says so,
/// held through a handle that keeps its ID from naming any other process.
///
/// [`terminate`]: Self::terminate
pub(crate) struct ProcessHandle {
    /// Process handle with query-limited-information and synchronize access.
    process: OwnedHandle,
    /// Whether the handle also has terminate access.
    terminate: bool,
}

impl ProcessHandle {
    /// Whether the process's exit wakes its waiters, which it always does on Windows.
    pub(crate) fn has_exit_event(&self) -> bool {
        true
    }

    /// Waits until the process exits or `deadline` passes, and returns whether it exited.
    pub(crate) fn wait(&self, deadline: Instant) -> io::Result<Option<bool>> {
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            // Round up, so that a wait shorter than a millisecond does not spin, and never wait
            // for INFINITE.
            let milliseconds = u32::try_from(left.as_nanos().div_ceil(1_000_000))
                .map_or(INFINITE - 1, |value| value.min(INFINITE - 1));
            // SAFETY: the handle has synchronize access.
            match unsafe { WaitForSingleObject(raw(&self.process), milliseconds) } {
                WAIT_OBJECT_0 => return Ok(Some(true)),
                WAIT_TIMEOUT if Instant::now() >= deadline => return Ok(Some(false)),
                WAIT_TIMEOUT => {}
                _ => return Err(io::Error::last_os_error()),
            }
        }
    }

    /// Terminates the process with status 1, unless it has exited, and fails if this user may
    /// not terminate process `pid`.
    pub(crate) fn kill(&self, pid: u32) -> io::Result<()> {
        if !self.terminate {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("this user may not terminate process {pid}"),
            ));
        }
        // SAFETY: the handle has terminate access.
        if unsafe { TerminateProcess(raw(&self.process), 1) } == 0 {
            let error = io::Error::last_os_error();
            // An exited process cannot be terminated again.
            if !has_exited(&self.process)? {
                return Err(error);
            }
        }
        Ok(())
    }
}

/// Opens the process `pid` if it still runs with the creation time `start_time`, and returns
/// `None` if it has exited, even if another process now has its ID.
///
/// The handle pins the process before its identity is checked. A process that does not let this
/// user query it and wait for it belongs to another user, so it is not a process that this user
/// started, and counts as exited too.
pub(crate) fn open_process(pid: u32, start_time: u64) -> io::Result<Option<ProcessHandle>> {
    let access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE;
    let handle = match open_handle(pid, access | PROCESS_TERMINATE) {
        Some(process) => Some(ProcessHandle {
            process,
            terminate: true,
        }),
        None => match last_error() {
            ERROR_INVALID_PARAMETER => None,
            ERROR_ACCESS_DENIED => {
                open_existing_process(pid, access)?.map(|process| ProcessHandle {
                    process,
                    terminate: false,
                })
            }
            error => return Err(io::Error::from_raw_os_error(error as i32)),
        },
    };
    let Some(handle) = handle else {
        return Ok(None);
    };
    if has_exited(&handle.process)? || creation_time(&handle.process)? != start_time {
        return Ok(None);
    }
    Ok(Some(handle))
}

/// Returns the identity of the current boot: the boot counter that Windows keeps in the registry
/// value `BootId` of [`BOOT_ID_KEY`] and changes at every boot, little-endian and zero-extended
/// to 16 bytes.
pub(crate) fn boot_id() -> io::Result<[u8; 16]> {
    let key = wide(BOOT_ID_KEY);
    let name = wide("BootId");
    let mut value = 0u32;
    let mut size = mem::size_of::<u32>() as u32;
    // SAFETY: the names are NUL-terminated, the type flag admits only a REG_DWORD, and the
    // output buffer holds `size` bytes.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_DWORD,
            ptr::null_mut(),
            (&raw mut value).cast(),
            &mut size,
        )
    };
    if status != ERROR_SUCCESS {
        let error = io::Error::from_raw_os_error(status as i32);
        return Err(io::Error::new(
            error.kind(),
            format!("cannot read the registry value HKLM\\{BOOT_ID_KEY}\\BootId: {error}"),
        ));
    }
    let mut id = [0; 16];
    id[..4].copy_from_slice(&value.to_le_bytes());
    Ok(id)
}

/// The registry key of the boot counter, under `HKEY_LOCAL_MACHINE`.
const BOOT_ID_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters";

/// An OpenVMM process launched by this caller, held through its process handle.
pub(crate) struct LaunchedProcess {
    /// Process handle retained for termination and waiting.
    process: OwnedHandle,
    /// Numeric process identifier reported to instance state.
    pid: u32,
}

impl LaunchedProcess {
    /// Returns the numeric process identifier.
    pub(crate) fn id(&self) -> u32 {
        self.pid
    }

    /// Holds the process through a handle of its own, which outlives this one, and returns it
    /// with the process's creation time.
    pub(crate) fn pin(&self) -> io::Result<(ProcessHandle, u64)> {
        let process = self.process.try_clone()?;
        let start_time = creation_time(&process)?;
        Ok((
            ProcessHandle {
                process,
                terminate: true,
            },
            start_time,
        ))
    }

    /// Terminates the process and returns whether it exited within `timeout`.
    pub(crate) fn terminate(self, timeout: Duration) -> bool {
        // SAFETY: CreateProcessW returned the handle with full access.
        unsafe { TerminateProcess(raw(&self.process), 1) };
        let milliseconds = u32::try_from(timeout.as_millis()).unwrap_or(INFINITE - 1);
        // SAFETY: as above.
        unsafe { WaitForSingleObject(raw(&self.process), milliseconds) == WAIT_OBJECT_0 }
    }

    /// Waits up to `timeout` for the process to exit, and returns its exit status if it has,
    /// as `Popen.wait` reads it with `GetExitCodeProcess`.
    #[cfg(feature = "cli")]
    pub(crate) fn wait_timeout(&self, timeout: Duration) -> io::Result<Option<u32>> {
        let milliseconds = u32::try_from(timeout.as_millis()).unwrap_or(INFINITE - 1);
        // SAFETY: CreateProcessW returned the handle with full access.
        match unsafe { WaitForSingleObject(raw(&self.process), milliseconds) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => return Ok(None),
            _ => return Err(io::Error::last_os_error()),
        }
        let mut status = 0u32;
        // SAFETY: as above, and the output pointer is valid.
        if unsafe { GetExitCodeProcess(raw(&self.process), &mut status) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(status))
    }

    /// Asks the process to end with status 1 without waiting for it, as `Popen.terminate` and
    /// `Popen.kill` do on Windows.
    #[cfg(feature = "cli")]
    pub(crate) fn request_termination(&self) -> io::Result<()> {
        // SAFETY: CreateProcessW returned the handle with full access.
        if unsafe { TerminateProcess(raw(&self.process), 1) } == 0 {
            let error = io::Error::last_os_error();
            // A process that already exited cannot be terminated; Python ignores that too.
            if self.wait_timeout(Duration::ZERO)?.is_none() {
                return Err(error);
            }
        }
        Ok(())
    }
}

/// Owns an initialized process-thread attribute list.
struct AttributeList {
    /// Backing storage, kept `usize`-aligned for the opaque list structure.
    buffer: Vec<usize>,
}

impl AttributeList {
    /// Allocates and initializes a list with room for `count` attributes.
    fn new(count: u32) -> io::Result<Self> {
        let mut size = 0;
        // SAFETY: a null list with a size pointer only queries the required size.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), count, 0, &mut size) };
        let mut buffer = vec![0; size.div_ceil(mem::size_of::<usize>())];
        // SAFETY: the buffer holds at least `size` bytes.
        if unsafe {
            InitializeProcThreadAttributeList(buffer.as_mut_ptr().cast(), count, 0, &mut size)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { buffer })
    }

    /// Returns the mutable opaque-list pointer used by Win32 process APIs.
    fn as_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.buffer.as_mut_ptr().cast()
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: the list was initialized in `new`.
        unsafe { DeleteProcThreadAttributeList(self.as_ptr()) };
    }
}

/// Starts OpenVMM without the caller's console so it outlives the caller.
///
/// `std::process::Command` lets the child inherit every inheritable handle of the caller. A
/// caller whose own standard output is a pipe, such as a phase process whose parent collects
/// its output, would then hand that pipe to OpenVMM, and the parent would wait for the VM to
/// exit before seeing end-of-file. The handle list restricts inheritance to `stdio`.
///
/// The `stdio` handles are inheritable only from here until the caller drops them after the
/// spawn, so a process that the caller spawns concurrently through `std::process` could inherit
/// them in that window.
pub(crate) fn spawn_detached(
    program: &Path,
    arguments: &[OsString],
    working_dir: &Path,
    stdio: [OwnedHandle; 3],
    breakaway_from_job: bool,
) -> io::Result<LaunchedProcess> {
    let application = wide(program);
    let mut command_line = command_line(program.as_os_str(), arguments)?;
    let directory = wide(working_dir);
    let handles = stdio.each_ref().map(raw);
    for handle in handles {
        // SAFETY: the handle is open and owned by `stdio`.
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let mut attributes = AttributeList::new(1)?;
    // SAFETY: the list has room for one attribute, and `handles` outlives CreateProcessW.
    if unsafe {
        UpdateProcThreadAttribute(
            attributes.as_ptr(),
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles.as_ptr().cast(),
            mem::size_of_val(&handles),
            ptr::null_mut(),
            ptr::null(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: STARTUPINFOEXW is a plain C structure for which all-zero is a valid value.
    let mut startup: STARTUPINFOEXW = unsafe { mem::zeroed() };
    startup.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    [
        startup.StartupInfo.hStdInput,
        startup.StartupInfo.hStdOutput,
        startup.StartupInfo.hStdError,
    ] = handles;
    startup.lpAttributeList = attributes.as_ptr();
    let mut flags = CREATE_UNICODE_ENVIRONMENT
        | EXTENDED_STARTUPINFO_PRESENT
        | CREATE_NEW_PROCESS_GROUP
        | CREATE_NO_WINDOW;
    if breakaway_from_job {
        flags |= CREATE_BREAKAWAY_FROM_JOB;
    }
    // SAFETY: PROCESS_INFORMATION is a plain C structure for which all-zero is a valid value.
    let mut information: PROCESS_INFORMATION = unsafe { mem::zeroed() };
    // SAFETY: every string is NUL-terminated, the command line is mutable, and the startup
    // information and attribute list stay alive for the call.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            flags,
            ptr::null(),
            directory.as_ptr(),
            &startup.StartupInfo,
            &mut information,
        )
    };
    if created == 0 {
        return Err(io::Error::last_os_error());
    }
    drop(owned(information.hThread));
    let process = owned(information.hProcess)
        .ok_or_else(|| io::Error::other("CreateProcessW returned no process handle"))?;
    Ok(LaunchedProcess {
        process,
        pid: information.dwProcessId,
    })
}

/// Builds a NUL-terminated command line that the Microsoft C runtime splits back into
/// `program` and `arguments`.
fn command_line(program: &OsStr, arguments: &[OsString]) -> io::Result<Vec<u16>> {
    let mut line = Vec::new();
    for (index, argument) in std::iter::once(program)
        .chain(arguments.iter().map(OsString::as_os_str))
        .enumerate()
    {
        if index > 0 {
            line.push(u16::from(b' '));
        }
        append_argument(&mut line, argument, index == 0)?;
    }
    line.push(0);
    Ok(line)
}

/// Appends one argument using the Microsoft C runtime's backslash-and-quote rules.
fn append_argument(line: &mut Vec<u16>, argument: &OsStr, always_quote: bool) -> io::Result<()> {
    let units: Vec<u16> = argument.encode_wide().collect();
    if units.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "command-line arguments cannot contain NUL characters",
        ));
    }
    let (quote, backslash) = (u16::from(b'"'), u16::from(b'\\'));
    let quoted = always_quote
        || units.is_empty()
        || units
            .iter()
            .any(|&unit| unit == u16::from(b' ') || unit == u16::from(b'\t'));
    if quoted {
        line.push(quote);
    }
    let mut backslashes = 0;
    for unit in units {
        if unit == backslash {
            backslashes += 1;
        } else {
            if unit == quote {
                line.extend(std::iter::repeat_n(backslash, backslashes + 1));
            }
            backslashes = 0;
        }
        line.push(unit);
    }
    if quoted {
        line.extend(std::iter::repeat_n(backslash, backslashes));
        line.push(quote);
    }
    Ok(())
}

/// Checks that the Windows Hypervisor Platform is installed and reports a hypervisor.
///
/// `WinHvPlatform.dll` is loaded dynamically so hosts without the optional feature can still
/// load this crate.
pub(crate) fn probe_hypervisor(hypervisor: Hypervisor) -> Result<(), String> {
    if hypervisor != Hypervisor::Whp {
        return Err(format!("{hypervisor} is only available on Linux"));
    }
    type WhvGetCapability = unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;
    const HYPERVISOR_PRESENT: u32 = 0;

    let name = wide("WinHvPlatform.dll");
    // SAFETY: the name is NUL-terminated and the search is limited to System32.
    let module =
        unsafe { LoadLibraryExW(name.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if module.is_null() {
        return Err(
            "the Windows Hypervisor Platform is not installed (WinHvPlatform.dll is missing)"
                .to_owned(),
        );
    }
    // SAFETY: the module handle is valid and the symbol name is NUL-terminated.
    let symbol = unsafe { GetProcAddress(module, c"WHvGetCapability".as_ptr().cast()) };
    let result = symbol.map(|symbol| {
        // SAFETY: WHvGetCapability has this signature in every WinHvPlatform.dll.
        let get_capability: WhvGetCapability = unsafe { std::mem::transmute(symbol) };
        let mut present = 0i32;
        let mut written = 0u32;
        // SAFETY: the output buffer is a 4-byte BOOL, as the capability code requires.
        let status = unsafe {
            get_capability(
                HYPERVISOR_PRESENT,
                (&raw mut present).cast(),
                4,
                &mut written,
            )
        };
        (status, present)
    });
    // SAFETY: the module was loaded above and no function pointer from it outlives this call.
    unsafe { FreeLibrary(module) };
    match result {
        None => Err("WinHvPlatform.dll does not export WHvGetCapability".to_owned()),
        Some((status, _)) if status < 0 => Err(format!(
            "WHvGetCapability failed with HRESULT {status:#010x}"
        )),
        Some((_, 0)) => {
            Err("the Windows Hypervisor Platform reports that no hypervisor is present".to_owned())
        }
        Some(_) => Ok(()),
    }
}

/// Creates `path` if needed. The directory inherits the ACL of its parent, which is private to
/// the user under the default state root.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    if fs::symlink_metadata(path)?.is_dir() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{} is not a plain directory",
            path.display()
        )))
    }
}

/// Returns the volume serial number and file index of a file or directory.
///
/// The object is opened without access rights, which succeeds even while OpenVMM holds it open.
pub fn file_identity(path: &Path) -> io::Result<(u64, u64)> {
    let file = OpenOptions::new()
        .access_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    handle_identity(file.as_raw_handle() as HANDLE)
}

/// Returns the volume serial number and file index of the file that `file` holds open.
pub(crate) fn opened_file_identity(file: &fs::File) -> io::Result<(u64, u64)> {
    handle_identity(file.as_raw_handle() as HANDLE)
}

/// Returns the volume serial number and file index of the file that `handle` holds open.
fn handle_identity(handle: HANDLE) -> io::Result<(u64, u64)> {
    // SAFETY: BY_HANDLE_FILE_INFORMATION is plain data for which all-zero bytes are valid.
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { mem::zeroed() };
    // SAFETY: the caller passes an open handle, and the output pointer is valid.
    if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        u64::from(information.dwVolumeSerialNumber),
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    ))
}

/// Claims a launch's fresh log, which `file` holds open.
///
/// On Windows the claim is the open handle itself, which the VMM inherits: while any process
/// holds the log open, an open that shares nothing fails, so the claim needs no further step.
pub(crate) fn claim_log(_file: &fs::File) -> io::Result<()> {
    Ok(())
}

/// Returns whether a process still holds the claimed log at `path`, which must be the file
/// `identity`: whether any process holds it open.
///
/// An open without access rights takes no part in sharing checks, so the identity is checked
/// first; an open that shares nothing then fails with a sharing violation while any process,
/// such as a VMM that inherited the log, holds it. The identity is checked again on the
/// exclusive handle, because a rename between the opens could have replaced the file.
pub(crate) fn log_claim_held(path: &Path, identity: (u64, u64)) -> io::Result<bool> {
    let replaced = || io::Error::other(format!("{} is not the claimed log", path.display()));
    if file_identity(path)? != identity {
        return Err(replaced());
    }
    let exclusive = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path);
    match exclusive {
        Ok(file) if opened_file_identity(&file)? == identity => Ok(false),
        Ok(_) => Err(replaced()),
        Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) => Ok(true),
        Err(error) => Err(error),
    }
}

/// Returns whether the live process `pid` that started at `start_time`, which serves the control
/// endpoint of a launch whose log is the file `log`, is that launch's VMM.
///
/// On Windows it is: the endpoint is a named pipe whose name [`control_endpoint`] draws at random
/// for each launch, so only the VMM that the launch passed it to serves it. The objects of the
/// process are not examined, as a query of another process's synchronous pipe could wait forever.
pub(crate) fn serves_launch(_pid: u32, _start_time: u64, _log: (u64, u64)) -> io::Result<bool> {
    Ok(true)
}

/// Returns a fresh named-pipe endpoint for OpenVMM to listen on.
pub(crate) fn control_endpoint(_socket_path: &Path) -> io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    let suffix: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("//./pipe/openvmm-microvm-{suffix}"))
}

/// Connects to a named pipe served by the process `expected_pid`.
pub(crate) fn connect_endpoint(
    endpoint: &str,
    expected_pid: u32,
    timeout: Duration,
) -> io::Result<Box<dyn Transport>> {
    let name = wide(endpoint.replace('/', "\\"));
    // SAFETY: the name is NUL-terminated; SQOS identification prevents the server from
    // impersonating this client.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            ptr::null_mut(),
        )
    };
    let Some(pipe) = owned(handle) else {
        let error = last_error();
        if error == ERROR_PIPE_BUSY {
            let wait = u32::try_from(timeout.as_millis())
                .unwrap_or(u32::MAX)
                .max(1);
            // SAFETY: the name is NUL-terminated.
            unsafe { WaitNamedPipeW(name.as_ptr(), wait) };
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "control endpoint is busy",
            ));
        }
        return Err(io::Error::from_raw_os_error(error as i32));
    };
    let mut server = 0u32;
    // SAFETY: the handle is a connected pipe client and the output pointer is valid.
    if unsafe { GetNamedPipeServerProcessId(raw(&pipe), &mut server) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if server != expected_pid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "control endpoint is served by process {server}, not OpenVMM process {expected_pid}"
            ),
        ));
    }
    // SAFETY: creates an unnamed manual-reset event with default security.
    let event = owned(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })
        .ok_or_else(io::Error::last_os_error)?;
    Ok(Box::new(PipeTransport { pipe, event }))
}

/// Returns the process that serves a named-pipe endpoint, or `None` if the pipe does not exist.
///
/// OpenVMM keeps one pipe instance for its whole lifetime, so a missing pipe means no OpenVMM
/// serves the endpoint. The instance is busy while a client is attached and briefly between
/// clients, which is waited out for up to five seconds.
pub(crate) fn endpoint_server_pid(endpoint: &str) -> io::Result<Option<u32>> {
    let name = wide(endpoint.replace('/', "\\"));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        // SAFETY: the name is NUL-terminated; SQOS identification prevents impersonation.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if let Some(pipe) = owned(handle) {
            let mut server = 0u32;
            // SAFETY: the handle is a connected pipe client and the output pointer is valid.
            if unsafe { GetNamedPipeServerProcessId(raw(&pipe), &mut server) } == 0 {
                return Err(io::Error::last_os_error());
            }
            return Ok(Some(server));
        }
        match last_error() {
            ERROR_FILE_NOT_FOUND => return Ok(None),
            ERROR_PIPE_BUSY if Instant::now() < deadline => {
                // SAFETY: the name is NUL-terminated.
                unsafe { WaitNamedPipeW(name.as_ptr(), 100) };
            }
            error => return Err(io::Error::from_raw_os_error(error as i32)),
        }
    }
}

/// Overlapped byte transport over OpenVMM's named-pipe control endpoint.
struct PipeTransport {
    /// Connected named-pipe client handle.
    pipe: OwnedHandle,
    /// Manual event reused to wait for each overlapped operation.
    event: OwnedHandle,
}

impl PipeTransport {
    /// Runs one overlapped operation to completion or timeout.
    ///
    /// `start` issues the operation. The function always waits for the operation to finish,
    /// cancelling it on timeout, so the `OVERLAPPED` and the caller's buffer outlive it.
    fn overlapped(
        &mut self,
        timeout: Option<Duration>,
        start: impl FnOnce(HANDLE, *mut OVERLAPPED) -> i32,
    ) -> io::Result<usize> {
        let pipe = raw(&self.pipe);
        // SAFETY: OVERLAPPED is plain data for which all-zero bytes are a valid initial state.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        // The event can be reused: ReadFile and WriteFile reset it to nonsignaled before they
        // start an operation.
        overlapped.hEvent = raw(&self.event);
        if start(pipe, &raw mut overlapped) == 0 {
            let error = last_error();
            if error != ERROR_IO_PENDING {
                return completion_error(error, 0, false);
            }
        }
        let wait = timeout.map_or(INFINITE, |timeout| {
            u32::try_from(timeout.as_millis())
                .unwrap_or(INFINITE - 1)
                .clamp(1, INFINITE - 1)
        });
        // SAFETY: the event belongs to this transport.
        let signaled = unsafe { WaitForSingleObject(overlapped.hEvent, wait) } == WAIT_OBJECT_0;
        if !signaled {
            // SAFETY: cancels only the operation that uses this OVERLAPPED.
            unsafe { CancelIoEx(pipe, &overlapped) };
        }
        let mut transferred = 0u32;
        // SAFETY: waits for the operation to finish, so nothing references `overlapped` after.
        if unsafe { GetOverlappedResult(pipe, &overlapped, &mut transferred, 1) } != 0 {
            return Ok(transferred as usize);
        }
        completion_error(last_error(), transferred as usize, !signaled)
    }
}

/// Maps a completed pipe operation's Win32 status to Rust I/O semantics.
fn completion_error(error: u32, transferred: usize, timed_out: bool) -> io::Result<usize> {
    match error {
        ERROR_OPERATION_ABORTED if timed_out => Err(io::ErrorKind::TimedOut.into()),
        ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_NO_DATA => Ok(0),
        ERROR_MORE_DATA => Ok(transferred),
        _ => Err(io::Error::from_raw_os_error(error as i32)),
    }
}

impl Transport for PipeTransport {
    fn read(&mut self, buffer: &mut [u8], timeout: Option<Duration>) -> io::Result<usize> {
        let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        let data = buffer.as_mut_ptr();
        self.overlapped(timeout, |pipe, overlapped| {
            // SAFETY: `data` is valid for `length` bytes until the operation completes, which
            // `overlapped` guarantees before returning.
            unsafe { ReadFile(pipe, data, length, ptr::null_mut(), overlapped) }
        })
    }

    fn write_all(&mut self, mut data: &[u8], timeout: Option<Duration>) -> io::Result<()> {
        // One deadline bounds the whole write, however the endpoint splits it.
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        while !data.is_empty() {
            let left = super::time_left(deadline)?;
            let length = u32::try_from(data.len()).unwrap_or(u32::MAX);
            let pointer = data.as_ptr();
            let written = self.overlapped(left, |pipe, overlapped| {
                // SAFETY: as for reads, the buffer outlives the operation.
                unsafe { WriteFile(pipe, pointer, length, ptr::null_mut(), overlapped) }
            })?;
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            data = &data[written..];
        }
        Ok(())
    }
}

/// Whether Ctrl-C reached the console since [`watch_interrupts`] installed its handler.
#[cfg(feature = "cli")]
static INTERRUPTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The console control handler, which records Ctrl-C and leaves every other event, such as
/// Ctrl-Break, to the next handler, which terminates the process.
#[cfg(feature = "cli")]
unsafe extern "system" fn record_interrupt(control: u32) -> windows_sys::core::BOOL {
    if control == CTRL_C_EVENT {
        INTERRUPTED.store(true, std::sync::atomic::Ordering::SeqCst);
        1
    } else {
        0
    }
}

/// Records each Ctrl-C for [`interrupted`] instead of letting it terminate the process, as
/// Python's `SIGINT` handler, which raises `KeyboardInterrupt`, does. Ctrl-Break still
/// terminates it, as it terminates Python.
#[cfg(feature = "cli")]
pub(crate) fn watch_interrupts() -> io::Result<()> {
    // SAFETY: the handler only stores to an atomic, and stays valid for the process's lifetime.
    if unsafe { SetConsoleCtrlHandler(Some(record_interrupt), 1) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Returns whether Ctrl-C reached the console since [`watch_interrupts`].
#[cfg(feature = "cli")]
pub(crate) fn interrupted() -> bool {
    INTERRUPTED.load(std::sync::atomic::Ordering::SeqCst)
}

/// Locks the first byte of `file` unless another handle holds a lock on it, as
/// `msvcrt.locking(fd, LK_NBLCK, 1)` does at offset 0, and returns whether it took the lock.
///
/// Like the C runtime, which reports every failure of `LockFile` as `EACCES` in this mode, any
/// failure counts as a lock that another handle holds.
#[cfg(feature = "cli")]
pub(crate) fn try_lock_first_byte(file: &fs::File) -> bool {
    // SAFETY: the handle is open for as long as `file` is borrowed.
    unsafe { LockFile(file.as_raw_handle() as HANDLE, 0, 0, 1, 0) != 0 }
}

/// Unlocks the first byte of `file`, as `msvcrt.locking(fd, LK_UNLCK, 1)` does at offset 0.
#[cfg(feature = "cli")]
pub(crate) fn unlock_first_byte(file: &fs::File) -> io::Result<()> {
    // SAFETY: the handle is open for as long as `file` is borrowed.
    if unsafe { UnlockFile(file.as_raw_handle() as HANDLE, 0, 0, 1, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    fn line(program: &str, arguments: &[&str]) -> String {
        let arguments: Vec<OsString> = arguments.iter().map(OsString::from).collect();
        let mut units = command_line(OsStr::new(program), &arguments).unwrap();
        assert_eq!(units.pop(), Some(0));
        String::from_utf16(&units).unwrap()
    }

    #[test]
    fn command_lines_follow_the_c_runtime_rules() {
        assert_eq!(
            line(r"C:\Program Files\openvmm.exe", &["--a", "b c", ""]),
            r#""C:\Program Files\openvmm.exe" --a "b c" """#
        );
        assert_eq!(line("x", &[r#"say "hi""#]), r#""x" "say \"hi\"""#);
        assert_eq!(line("x", &[r#"a"b"#]), r#""x" a\"b"#);
        assert_eq!(line("x", &[r"dir\ with\"]), r#""x" "dir\ with\\""#);
        assert_eq!(line("x", &[r"a\\b"]), r#""x" a\\b"#);
        assert!(command_line(OsStr::new("x"), &[OsString::from("a\0b")]).is_err());
    }

    #[test]
    fn children_inherit_only_their_standard_handles() {
        // An inheritable pipe stands in for a caller's own redirected standard output.
        let (mut leaked_reader, leaked_writer) = io::pipe().unwrap();
        let leaked = OwnedHandle::from(leaked_writer);
        // SAFETY: the handle is open and owned above.
        assert_ne!(
            unsafe { SetHandleInformation(raw(&leaked), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) },
            0
        );
        let (stdin, _stdin_writer) = io::pipe().unwrap();
        let (_stdout_reader, stdout) = io::pipe().unwrap();
        let stderr = stdout.try_clone().unwrap();
        let system = std::env::var_os("SystemRoot").unwrap();
        let cmd = Path::new(&system).join("System32").join("cmd.exe");
        let child = spawn_detached(
            &cmd,
            &[OsString::from("/c"), OsString::from("ping -n 30 127.0.0.1")],
            &std::env::temp_dir(),
            [stdin.into(), stdout.into(), stderr.into()],
            false,
        )
        .unwrap();

        // The running child holds no copy of the leaked pipe, so closing ours ends it.
        drop(leaked);
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut rest = Vec::new();
            let _ = sender.send(leaked_reader.read_to_end(&mut rest).map(|_| rest));
        });
        let rest = receiver.recv_timeout(Duration::from_secs(5));
        assert!(child.terminate(Duration::from_secs(10)));
        assert!(
            rest.expect("the child inherited the caller's pipe")
                .unwrap()
                .is_empty()
        );
    }
}
