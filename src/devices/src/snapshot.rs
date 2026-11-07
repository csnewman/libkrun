//! Device snapshot seam.
//!
//! Devices live in this crate, so the trait they implement lives here too (the
//! VMM cannot be a dependency — it depends on us). The VMM orchestrates capture
//! by iterating `dyn Snapshottable` and maps the returned bytes/errors into its
//! snapshot format.

use crate::Error;

/// Opaque, independently-versioned per-device state. The device owns the byte
/// layout; the orchestrator only frames it (id + length + version).
pub struct SavedState {
    pub version: u8,
    pub bytes: Vec<u8>,
}

/// A device that can serialize and restore its runtime state. Implemented by
/// the transports and legacy devices that must survive a snapshot; iterated as
/// a trait object by the VMM, which is why it stays object-safe.
pub trait Snapshottable: Send {
    /// Quiesce the device so [`Snapshottable::save`] sees consistent state.
    /// Stops the worker threads that own the live queue indices.
    fn pause(&mut self) -> Result<(), Error> {
        Ok(())
    }

    /// Capture runtime state. Must be called after [`Snapshottable::pause`].
    fn save(&self) -> Result<SavedState, Error>;

    /// Load saved state, leaving the device quiesced (workers stopped).
    fn restore(&mut self, state: &SavedState) -> Result<(), Error>;

    /// Start the workers again, on the state [`Snapshottable::pause`] stopped
    /// or [`Snapshottable::restore`] loaded. Separate from `restore`: a worker
    /// raises interrupts as soon as it runs, so it starts only once the
    /// interrupt controller's state is in.
    fn resume(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
