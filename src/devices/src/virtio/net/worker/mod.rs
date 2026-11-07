#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{NetWorker, NetWorkerHandle};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::NetWorker;
