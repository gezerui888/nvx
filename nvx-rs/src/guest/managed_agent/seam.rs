use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};

use crate::guest::spawn::{Command, Spawned};
use crate::guest::sys::{self, Errno, FileDescriptor, Mode, MountFlags, OpenFlags};

/// Production paths used by the managed agent and replaceable paths used by tests.
#[derive(Clone, Debug)]
pub(crate) struct Paths {
    /// Unified cgroup-v2 root.
    pub(crate) cgroup_root: PathBuf,
    /// Sandbox container cgroup membership file.
    pub(crate) container_cgroup_procs: PathBuf,
    /// Parent of OpenVMM's aggregate host-filesystem exports.
    pub(crate) hostfs_dir: PathBuf,
    /// Kernel command line containing the announced mapping count.
    pub(crate) proc_cmdline: PathBuf,
    /// Port device used for fatal diagnostics.
    pub(crate) diagnostic_port: PathBuf,
    /// Null device used for child standard input.
    pub(crate) null_device: PathBuf,
    /// FIFO that releases a sandbox launcher.
    pub(crate) barrier: PathBuf,
    /// Managed-agent helper executable.
    pub(crate) helper: PathBuf,
    /// Sandbox container launcher.
    pub(crate) launcher: PathBuf,
    /// VM exit helper.
    pub(crate) exit: PathBuf,
    /// Privilege-dropping launcher used in direct mode.
    pub(crate) setpriv: PathBuf,
}

impl Default for Paths {
    /// Returns the paths installed in production guest images.
    fn default() -> Self {
        Self {
            cgroup_root: "/sys/fs/cgroup".into(),
            container_cgroup_procs: "/sys/fs/cgroup/container/cgroup.procs".into(),
            hostfs_dir: "/run/nvx/hostfs".into(),
            proc_cmdline: "/proc/cmdline".into(),
            diagnostic_port: "/dev/port".into(),
            null_device: "/dev/null".into(),
            barrier: "/run/nvx/managed-container-start".into(),
            helper: "/sbin/nvx-managed-agent".into(),
            launcher: "/sbin/nvx-container-launch".into(),
            exit: "/sbin/nvx-exit".into(),
            setpriv: "/bin/setpriv".into(),
        }
    }
}

/// Replaceable boundary for privileged and process-global operations.
pub(crate) trait System {
    /// Returns the production or test path set.
    fn paths(&self) -> &Paths;

    /// Performs one mount or bind-remount operation.
    fn mount(
        &mut self,
        source: Option<&CStr>,
        target: &CStr,
        filesystem: Option<&CStr>,
        flags: MountFlags,
    ) -> Result<(), Errno>;

    /// Changes path ownership.
    fn chown(&mut self, path: &CStr, uid: u32, gid: u32) -> Result<(), Errno>;
    /// Changes path mode bits.
    fn chmod(&mut self, path: &CStr, mode: Mode) -> Result<(), Errno>;
    /// Configures the control terminal.
    fn configure_tty(&mut self, descriptor: &FileDescriptor) -> Result<(), Errno>;
    /// Drains pending control-terminal output.
    fn drain_tty(&mut self, descriptor: &FileDescriptor) -> Result<(), Errno>;
    /// Writes one diagnostic line through port 0xE9.
    fn write_diagnostic(&mut self, message: &[u8]) -> Result<(), Errno>;
    /// Writes the sandbox launch barrier.
    fn write_barrier(&mut self, descriptor: &FileDescriptor, message: &[u8]) -> Result<(), Errno>;
    /// Returns an owned duplicate of the helper's inherited configuration descriptor, which then
    /// closes on `exec`.
    fn take_inherited_descriptor(&mut self, text: &CStr) -> Result<FileDescriptor, Errno>;
    /// Validates one variable that an environment receives, without setting it.
    ///
    /// Production accepts every variable: building an environment in memory cannot fail where C's
    /// environment functions could. Tests reject one to cover the C failure paths.
    fn validate_environment(&mut self, name: &CStr, value: &CStr) -> Result<(), Errno>;
    /// Replaces the current process image, with `environment` or the current one.
    fn exec(
        &mut self,
        path: &CStr,
        arguments: &[CString],
        environment: Option<&[CString]>,
    ) -> Result<(), Errno>;
    /// Spawns one workload's launch command.
    fn spawn(&mut self, command: Command) -> Result<Spawned, Errno>;
}

/// Production implementation backed exclusively by safe `guest::sys` APIs.
pub(crate) struct RealSystem {
    /// Production path set.
    paths: Paths,
}

impl RealSystem {
    /// Creates a production system seam with `paths`.
    pub(crate) fn new(paths: Paths) -> Self {
        Self { paths }
    }
}

impl System for RealSystem {
    fn paths(&self) -> &Paths {
        &self.paths
    }

    fn mount(
        &mut self,
        source: Option<&CStr>,
        target: &CStr,
        filesystem: Option<&CStr>,
        flags: MountFlags,
    ) -> Result<(), Errno> {
        sys::mount(source, target, filesystem, flags)
    }

    fn chown(&mut self, path: &CStr, uid: u32, gid: u32) -> Result<(), Errno> {
        sys::chown(path, uid, gid)
    }

    fn chmod(&mut self, path: &CStr, mode: Mode) -> Result<(), Errno> {
        sys::chmod(path, mode)
    }

    fn configure_tty(&mut self, descriptor: &FileDescriptor) -> Result<(), Errno> {
        sys::configure_raw(descriptor)
    }

    fn drain_tty(&mut self, descriptor: &FileDescriptor) -> Result<(), Errno> {
        sys::drain(descriptor)
    }

    fn write_diagnostic(&mut self, message: &[u8]) -> Result<(), Errno> {
        let path = path_c_string(&self.paths.diagnostic_port)?;
        let descriptor = sys::open(
            &path,
            OpenFlags::O_WRONLY | OpenFlags::O_CLOEXEC,
            Mode::empty(),
        )?;
        sys::write_port_diagnostic(&descriptor, message)
    }

    fn write_barrier(&mut self, descriptor: &FileDescriptor, message: &[u8]) -> Result<(), Errno> {
        descriptor.write_all(message)
    }

    fn take_inherited_descriptor(&mut self, text: &CStr) -> Result<FileDescriptor, Errno> {
        sys::take_inherited_descriptor(text)
    }

    fn validate_environment(&mut self, _name: &CStr, _value: &CStr) -> Result<(), Errno> {
        Ok(())
    }

    fn exec(
        &mut self,
        path: &CStr,
        arguments: &[CString],
        environment: Option<&[CString]>,
    ) -> Result<(), Errno> {
        Err(sys::exec(path, arguments, environment))
    }

    fn spawn(&mut self, command: Command) -> Result<Spawned, Errno> {
        command.spawn().map_err(|error| sys::errno_of(&error))
    }
}

/// Converts a path through the system layer for use by the seam and callers.
pub(crate) fn path_c_string(path: &Path) -> Result<CString, Errno> {
    sys::path_c_string(path)
}

/// One recorded `exec`: the path, the arguments, and the environment if it had one.
#[cfg(test)]
pub(crate) type RecordedExec = (Vec<u8>, Vec<Vec<u8>>, Option<Vec<Vec<u8>>>);

#[cfg(test)]
pub(crate) struct TestSystem {
    pub(crate) paths: Paths,
    pub(crate) mounts: Vec<(Option<Vec<u8>>, Vec<u8>, MountFlags)>,
    pub(crate) fail_mount_call: Option<usize>,
    pub(crate) diagnostics: Vec<u8>,
    pub(crate) fail_environment: Option<Vec<u8>>,
    pub(crate) execs: Vec<RecordedExec>,
    pub(crate) spawn_calls: usize,
    /// Spawns each workload's launch command when set; `spawn` otherwise fails with `ENOSYS`.
    pub(crate) spawner: Option<fn(Command) -> Result<Spawned, Errno>>,
    pub(crate) tty_configured: usize,
    pub(crate) tty_drained: usize,
    pub(crate) close_barrier_reader: Option<FileDescriptor>,
    pub(crate) fail_barrier_write: Option<Errno>,
    /// Owned descriptors awaiting a simulated helper-entry transfer.
    pub(crate) inherited_descriptors: Vec<(Vec<u8>, FileDescriptor)>,
}

#[cfg(test)]
impl TestSystem {
    pub(crate) fn new(paths: Paths) -> Self {
        Self {
            paths,
            mounts: Vec::new(),
            fail_mount_call: None,
            diagnostics: Vec::new(),
            fail_environment: None,
            execs: Vec::new(),
            spawn_calls: 0,
            spawner: None,
            tty_configured: 0,
            tty_drained: 0,
            close_barrier_reader: None,
            fail_barrier_write: None,
            inherited_descriptors: Vec::new(),
        }
    }

    /// Registers one owned descriptor and returns its simulated inherited argument.
    pub(crate) fn transfer_inherited_descriptor(&mut self, descriptor: FileDescriptor) -> CString {
        let argument = descriptor.argument();
        self.inherited_descriptors
            .push((argument.as_bytes().to_vec(), descriptor));
        argument
    }
}

#[cfg(test)]
impl System for TestSystem {
    fn paths(&self) -> &Paths {
        &self.paths
    }

    fn mount(
        &mut self,
        source: Option<&CStr>,
        target: &CStr,
        _filesystem: Option<&CStr>,
        flags: MountFlags,
    ) -> Result<(), Errno> {
        self.mounts.push((
            source.map(|source| source.to_bytes().to_vec()),
            target.to_bytes().to_vec(),
            flags,
        ));
        if self.fail_mount_call == Some(self.mounts.len()) {
            Err(Errno::ENOENT)
        } else {
            Ok(())
        }
    }

    fn chown(&mut self, _path: &CStr, _uid: u32, _gid: u32) -> Result<(), Errno> {
        Ok(())
    }

    fn chmod(&mut self, _path: &CStr, _mode: Mode) -> Result<(), Errno> {
        Ok(())
    }

    fn configure_tty(&mut self, _descriptor: &FileDescriptor) -> Result<(), Errno> {
        self.tty_configured += 1;
        Ok(())
    }

    fn drain_tty(&mut self, _descriptor: &FileDescriptor) -> Result<(), Errno> {
        self.tty_drained += 1;
        Ok(())
    }

    fn write_diagnostic(&mut self, message: &[u8]) -> Result<(), Errno> {
        self.diagnostics.extend_from_slice(message);
        Ok(())
    }

    fn write_barrier(&mut self, descriptor: &FileDescriptor, message: &[u8]) -> Result<(), Errno> {
        self.close_barrier_reader = None;
        if let Some(error) = self.fail_barrier_write {
            return Err(error);
        }
        descriptor.write_all(message)
    }

    fn take_inherited_descriptor(&mut self, text: &CStr) -> Result<FileDescriptor, Errno> {
        let index = self
            .inherited_descriptors
            .iter()
            .position(|(argument, _)| argument == text.to_bytes())
            .ok_or(Errno::EBADF)?;
        Ok(self.inherited_descriptors.swap_remove(index).1)
    }

    fn validate_environment(&mut self, name: &CStr, _value: &CStr) -> Result<(), Errno> {
        if self
            .fail_environment
            .as_deref()
            .is_some_and(|failure| failure == name.to_bytes())
        {
            Err(Errno::ENOMEM)
        } else {
            Ok(())
        }
    }

    fn exec(
        &mut self,
        path: &CStr,
        arguments: &[CString],
        environment: Option<&[CString]>,
    ) -> Result<(), Errno> {
        let bytes = |strings: &[CString]| {
            strings
                .iter()
                .map(|string| string.as_bytes().to_vec())
                .collect::<Vec<_>>()
        };
        self.execs.push((
            path.to_bytes().to_vec(),
            bytes(arguments),
            environment.map(bytes),
        ));
        Ok(())
    }

    fn spawn(&mut self, command: Command) -> Result<Spawned, Errno> {
        self.spawn_calls += 1;
        match self.spawner {
            Some(spawner) => spawner(command),
            None => Err(Errno::ENOSYS),
        }
    }
}

/// Spawns a launch command as the privileged agent does, without privileges: the child's
/// credential calls are replaced and succeed, and it enters the working directory with the test's
/// own credentials.
#[cfg(test)]
pub(crate) fn spawn_as_privileged(command: Command) -> Result<Spawned, Errno> {
    command
        .simulate_credentials(None)
        .spawn()
        .map_err(|error| sys::errno_of(&error))
}

/// Spawns a launch command whose replaced credential calls fail with `EPERM`, as `setgroups`
/// does without privileges.
#[cfg(test)]
pub(crate) fn spawn_with_failing_credentials(command: Command) -> Result<Spawned, Errno> {
    command
        .simulate_credentials(Some(Errno::EPERM))
        .spawn()
        .map_err(|error| sys::errno_of(&error))
}

/// Writes an executable stand-in for `setpriv` in `directory` and returns its path.
///
/// The stand-in runs the shell command `action`, then executes the workload that follows the
/// helper's `--` separator, without changing credentials and without the helper. `action` runs
/// after the direct child has entered its working directory and before the workload runs.
#[cfg(test)]
pub(crate) fn setpriv_shim(directory: &Path, action: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let path = directory.join("setpriv");
    let script = format!(
        "#!/bin/sh\nset -e\n{action}\nwhile [ \"$#\" -gt 0 ]; do\n    argument=$1\n    shift\n    \
         if [ \"$argument\" = -- ]; then\n        break\n    fi\ndone\nexec \"$@\"\n"
    );
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}
