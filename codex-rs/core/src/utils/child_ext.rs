use std::pin::Pin;
use std::process::ExitStatus;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(windows)]
use std::os::windows::process::ExitStatusExt;
use std::future::Future;
use tokio::io::{self, AsyncRead, AsyncWriteExt, DuplexStream, duplex};
use tokio::process::{Child, ChildStderr, ChildStdout};

/// Represents a child process created from internal command results.
/// This avoids spawning a real OS process while still exposing an API
/// similar to [`tokio::process::Child`].
pub struct InternalChild {
    stdout: Option<DuplexStream>,
    stderr: Option<DuplexStream>,
    waited: bool,
}

impl InternalChild {
    pub fn new(stdout_data: String, stderr_data: String) -> Self {
        let (mut out_write, out_read) = duplex(stdout_data.len() + 1);
        tokio::spawn(async move {
            let _ = out_write.write_all(stdout_data.as_bytes()).await;
        });
        let (mut err_write, err_read) = duplex(stderr_data.len() + 1);
        tokio::spawn(async move {
            let _ = err_write.write_all(stderr_data.as_bytes()).await;
        });
        Self {
            stdout: Some(out_read),
            stderr: Some(err_read),
            waited: false,
        }
    }
}

/// Trait abstracting the minimal interface required by
/// [`consume_truncated_output`](crate::exec::consume_truncated_output).
pub trait ChildLike {
    type Stdout: AsyncRead + Unpin + Send + 'static;
    type Stderr: AsyncRead + Unpin + Send + 'static;

    fn take_stdout(&mut self) -> Option<Self::Stdout>;
    fn take_stderr(&mut self) -> Option<Self::Stderr>;
    fn start_kill(&mut self) -> io::Result<()>;
    fn wait_future<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<ExitStatus>> + Send + 'a>>;
}

impl ChildLike for Child {
    type Stdout = ChildStdout;
    type Stderr = ChildStderr;

    fn take_stdout(&mut self) -> Option<Self::Stdout> {
        self.stdout.take()
    }

    fn take_stderr(&mut self) -> Option<Self::Stderr> {
        self.stderr.take()
    }

    fn start_kill(&mut self) -> io::Result<()> {
        self.start_kill()
    }

    fn wait_future<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<ExitStatus>> + Send + 'a>> {
        Box::pin(async move { self.wait().await })
    }
}

impl ChildLike for InternalChild {
    type Stdout = DuplexStream;
    type Stderr = DuplexStream;

    fn take_stdout(&mut self) -> Option<Self::Stdout> {
        self.stdout.take()
    }

    fn take_stderr(&mut self) -> Option<Self::Stderr> {
        self.stderr.take()
    }

    fn start_kill(&mut self) -> io::Result<()> {
        // Nothing to kill
        Ok(())
    }

    fn wait_future<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<ExitStatus>> + Send + 'a>> {
        self.waited = true;
        Box::pin(async move { Ok(ExitStatus::from_raw(0)) })
    }
}

/// Enum unifying real and synthetic child processes.
pub enum BlackBoxChild {
    Real(Child),
    Internal(InternalChild),
}

impl ChildLike for BlackBoxChild {
    type Stdout = Box<dyn AsyncRead + Unpin + Send + 'static>;
    type Stderr = Box<dyn AsyncRead + Unpin + Send + 'static>;

    fn take_stdout(&mut self) -> Option<Self::Stdout> {
        match self {
            BlackBoxChild::Real(c) => c.take_stdout().map(|s| Box::new(s) as _),
            BlackBoxChild::Internal(c) => c.take_stdout().map(|s| Box::new(s) as _),
        }
    }

    fn take_stderr(&mut self) -> Option<Self::Stderr> {
        match self {
            BlackBoxChild::Real(c) => c.take_stderr().map(|s| Box::new(s) as _),
            BlackBoxChild::Internal(c) => c.take_stderr().map(|s| Box::new(s) as _),
        }
    }

    fn start_kill(&mut self) -> io::Result<()> {
        match self {
            BlackBoxChild::Real(c) => c.start_kill(),
            BlackBoxChild::Internal(c) => c.start_kill(),
        }
    }

    fn wait_future<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<ExitStatus>> + Send + 'a>> {
        match self {
            BlackBoxChild::Real(c) => c.wait_future(),
            BlackBoxChild::Internal(c) => c.wait_future(),
        }
    }
}

pub trait ChildExt {
    fn from_internal_results(stdout: String, stderr: String) -> BlackBoxChild;
}

impl ChildExt for Child {
    fn from_internal_results(stdout: String, stderr: String) -> BlackBoxChild {
        BlackBoxChild::Internal(InternalChild::new(stdout, stderr))
    }
}
