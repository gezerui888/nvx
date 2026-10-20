use std::os::unix::ffi::OsStrExt;

use crate::guest::parse::parse_decimal;
use crate::guest::spawn::{Cgroup, Command};
use crate::guest::sys::{self, Errno, FileDescriptor, Mode, OpenFlags, c_string};
use crate::protocol::GuestExecPayload;

use super::AgentConfig;
use super::environment;
use super::seam::{Paths, path_c_string};

/// One workload's launch inputs: its borrowed request, and the descriptors that its child takes.
pub(crate) struct LaunchRequest<'a> {
    /// Agent mode and configured workload identity.
    pub(crate) config: &'a AgentConfig,
    /// Decoded workload request.
    pub(crate) execution: &'a GuestExecPayload,
    /// Sealed helper configuration, which the child keeps open for the helper.
    pub(crate) config_fd: FileDescriptor,
    /// Writer of the workload's standard output.
    pub(crate) stdout: FileDescriptor,
    /// Writer of the workload's standard error.
    pub(crate) stderr: FileDescriptor,
}

/// Builds the command that launches one workload in the agent's mode.
///
/// In both modes the workload's standard input is the null device, its standard output and error
/// are the request's pipes, the sealed configuration stays open at its descriptor number, and the
/// child leads a new process group. The direct agent runs `setpriv`, which takes the workload's
/// identity and runs the helper; its child first enters the working directory as the workload,
/// records the physical path in `PWD` for a noncanonical name, and joins the execution cgroup.
/// The sandbox agent runs the container launcher, which enters the sandbox's root and identity.
pub(crate) fn command(paths: &Paths, request: LaunchRequest<'_>) -> Result<Command, Errno> {
    let config_fd = request.config_fd.argument();
    let directory = c_string(request.execution.cwd.as_deref().unwrap_or(b"/"))?;
    let uid = parse_id(request.config.uid.as_bytes())?;
    let gid = parse_id(request.config.gid.as_bytes())?;
    let helper = path_c_string(&paths.helper)?;
    let launcher = path_c_string(&paths.launcher)?;
    let setpriv = path_c_string(&paths.setpriv)?;
    let mut arguments = Vec::new();
    let program;
    let mut environment = environment::inherited()?;
    let mut physical_pwd = false;
    if request.config.direct {
        program = setpriv;
        for value in [
            b"setpriv".as_slice(),
            b"--reuid",
            request.config.uid.as_bytes(),
            b"--regid",
            request.config.gid.as_bytes(),
            b"--clear-groups",
            b"--no-new-privs",
            b"--bounding-set=-all",
            b"--inh-caps=-all",
            b"--ambient-caps=-all",
            helper.as_bytes(),
            b"--exec-config-fd",
            config_fd.as_bytes(),
            b"--",
        ] {
            arguments.push(c_string(value)?);
        }
        environment::set(&mut environment, b"HOME", request.config.home.as_bytes())?;
        environment::set(&mut environment, b"USER", request.config.user.as_bytes())?;
        environment::set(&mut environment, b"LOGNAME", request.config.user.as_bytes())?;
        if request.execution.environment.is_none() || request.execution.inherit_default_env {
            if directory.to_bytes() == b"/" || super::helper::safe_path(directory.to_bytes()) {
                environment::set(&mut environment, b"PWD", directory.to_bytes())?;
            } else {
                physical_pwd = true;
            }
        }
    } else {
        program = launcher.clone();
        for value in [
            launcher.as_bytes(),
            paths.barrier.as_os_str().as_bytes(),
            request.config.rootfs.as_bytes(),
            request.config.hostname.as_bytes(),
            request.config.uid.as_bytes(),
            request.config.gid.as_bytes(),
            request.config.user.as_bytes(),
            request.config.home.as_bytes(),
        ] {
            arguments.push(c_string(value)?);
        }
        environment::set(
            &mut environment,
            b"NVX_EXEC_CONFIG_FD",
            config_fd.as_bytes(),
        )?;
    }
    for argument in &request.execution.argv {
        arguments.push(c_string(argument)?);
    }
    let cgroup = if request.config.direct {
        let directory = paths.cgroup_root.join("nvx-exec");
        Some(Cgroup::open(&directory).map_err(|error| sys::errno_of(&error))?)
    } else {
        None
    };
    let null = sys::open(
        &path_c_string(&paths.null_device)?,
        OpenFlags::O_RDONLY | OpenFlags::O_CLOEXEC,
        Mode::empty(),
    )?;
    let mut command = Command::new(program, arguments)
        .environment(environment)
        .stdin(null)
        .stdout(request.stdout)
        .stderr(request.stderr)
        .inherit(request.config_fd)
        .new_process_group();
    if let Some(cgroup) = cgroup {
        command = command
            .working_directory(directory)
            .check_working_directory_as(uid, gid)
            .cgroup(cgroup);
        if physical_pwd {
            command = command.export_physical_working_directory();
        }
    }
    Ok(command)
}

/// Parses one nonzero decimal UID or GID while excluding the unchanged-ID sentinel.
fn parse_id(text: &[u8]) -> Result<u32, Errno> {
    parse_decimal(text)
        .filter(|&id| id != 0 && id < u64::from(u32::MAX))
        .and_then(|id| u32::try_from(id).ok())
        .ok_or(Errno::EINVAL)
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use crate::guest::sys::PreparedChild;
    use crate::protocol::GuestExecPayload;

    use super::*;

    fn config(direct: bool) -> AgentConfig {
        AgentConfig {
            rootfs: CString::new(if direct { "-" } else { "/rootfs" }).unwrap(),
            hostname: c"sandbox".to_owned(),
            uid: c"1000".to_owned(),
            gid: c"1001".to_owned(),
            user: c"workload".to_owned(),
            home: c"/home/workload".to_owned(),
            direct,
        }
    }

    fn execution() -> GuestExecPayload {
        GuestExecPayload {
            timeout_ms: 0,
            argv: vec![b"/bin/echo".to_vec(), b"ok".to_vec()],
            cwd: Some(b"/work".to_vec()),
            environment: None,
            inherit_default_env: false,
        }
    }

    fn descriptor() -> FileDescriptor {
        FileDescriptor::from_owned(tempfile::tempfile().unwrap().into())
    }

    /// Prepares the child that launches `execution` with `config`, and returns it with the
    /// number of its sealed configuration descriptor.
    fn prepare(
        paths: &Paths,
        config: &AgentConfig,
        execution: &GuestExecPayload,
    ) -> (PreparedChild, CString) {
        let config_fd = descriptor();
        let argument = config_fd.argument();
        let request = LaunchRequest {
            config,
            execution,
            config_fd,
            stdout: descriptor(),
            stderr: descriptor(),
        };
        (command(paths, request).unwrap().prepare(), argument)
    }

    #[test]
    fn direct_launch_uses_setpriv_and_clears_every_capability_set() {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::create_dir(temporary.path().join("nvx-exec")).unwrap();
        std::fs::write(temporary.path().join("nvx-exec/cgroup.procs"), b"").unwrap();
        let paths = Paths {
            cgroup_root: temporary.path().to_owned(),
            setpriv: "/test/setpriv".into(),
            helper: "/test/nvx-managed-agent".into(),
            ..Paths::default()
        };
        let config = config(true);
        let execution = execution();
        let (plan, descriptor_argument) = prepare(&paths, &config, &execution);
        let arguments: Vec<_> = plan
            .arguments()
            .iter()
            .map(|argument| argument.to_bytes())
            .collect();
        assert_eq!(
            arguments,
            [
                b"setpriv".as_slice(),
                b"--reuid",
                b"1000",
                b"--regid",
                b"1001",
                b"--clear-groups",
                b"--no-new-privs",
                b"--bounding-set=-all",
                b"--inh-caps=-all",
                b"--ambient-caps=-all",
                b"/test/nvx-managed-agent",
                b"--exec-config-fd",
                descriptor_argument.as_bytes(),
                b"--",
                b"/bin/echo",
                b"ok",
            ]
        );
        assert_eq!(plan.program().as_bytes(), b"/test/setpriv");
        let environment: Vec<_> = plan
            .environment()
            .iter()
            .map(|entry| entry.to_bytes())
            .collect();
        for expected in [
            b"HOME=/home/workload".as_slice(),
            b"USER=workload",
            b"LOGNAME=workload",
            b"PWD=/work",
        ] {
            assert!(environment.contains(&expected), "{expected:?}");
        }
        assert!(plan.has_cgroup());
    }

    #[test]
    fn sandbox_launch_exports_only_the_deliberate_config_descriptor() {
        let paths = Paths {
            launcher: "/test/nvx-container-launch".into(),
            barrier: "/test/start".into(),
            ..Paths::default()
        };
        let config = config(false);
        let execution = execution();
        let (plan, _) = prepare(&paths, &config, &execution);
        let arguments: Vec<_> = plan
            .arguments()
            .iter()
            .map(|argument| argument.to_bytes())
            .collect();
        assert_eq!(
            arguments,
            [
                b"/test/nvx-container-launch".as_slice(),
                b"/test/start",
                b"/rootfs",
                b"sandbox",
                b"1000",
                b"1001",
                b"workload",
                b"/home/workload",
                b"/bin/echo",
                b"ok",
            ]
        );
        assert!(
            plan.environment()
                .iter()
                .any(|entry| entry.as_bytes().starts_with(b"NVX_EXEC_CONFIG_FD="))
        );
        assert!(!plan.has_cgroup());
    }

    #[test]
    fn workload_ids_are_nonzero_decimal_and_not_the_unchanged_value() {
        for (text, expected) in [
            (b"1".as_slice(), Some(1)),
            (b"1000", Some(1000)),
            (b"4294967294", Some(u32::MAX - 1)),
            (b"0", None),
            (b"4294967295", None),
            (b"4294967296", None),
            (b"+1", None),
            (b"-1", None),
            (b" 1", None),
            (b"1x", None),
        ] {
            assert_eq!(parse_id(text).ok(), expected, "{text:?}");
        }
    }

    #[test]
    fn direct_pwd_is_deferred_only_for_noncanonical_names() {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::create_dir(temporary.path().join("nvx-exec")).unwrap();
        std::fs::write(temporary.path().join("nvx-exec/cgroup.procs"), b"").unwrap();
        let paths = Paths {
            cgroup_root: temporary.path().to_owned(),
            ..Paths::default()
        };
        let config = config(true);
        for cwd in [b"/a/./b".as_slice(), b"/a/../b", b"/a//b", b"/a/b/"] {
            let execution = GuestExecPayload {
                cwd: Some(cwd.to_vec()),
                ..execution()
            };
            let (plan, _) = prepare(&paths, &config, &execution);
            let slot = plan.physical_pwd().expect("PWD is deferred");
            assert_eq!(&slot[..4], b"PWD=");
            assert!(slot[4..].iter().all(|&byte| byte == 0));
            assert!(
                plan.environment()
                    .iter()
                    .all(|entry| !entry.as_bytes().starts_with(b"PWD="))
            );
            assert!(plan.physical_pwd_index().is_some());
            assert!(plan.has_cgroup());
        }

        let execution = GuestExecPayload {
            cwd: Some(b"/symlinked/component".to_vec()),
            ..execution()
        };
        let (plan, _) = prepare(&paths, &config, &execution);
        assert!(plan.physical_pwd().is_none());
        assert!(
            plan.environment()
                .iter()
                .any(|entry| entry.as_bytes() == b"PWD=/symlinked/component")
        );
        assert!(plan.has_cgroup());
    }
}
