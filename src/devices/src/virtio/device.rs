// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fmt;
use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard};

use super::{ActivateResult, Queue, QueueSnapshot, device_status};
use crate::virtio::AsAny;
use utils::eventfd::{EFD_NONBLOCK, EventFd};
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::GuestMemoryMmap;

/// Configuration for a single virtqueue.
/// This is used by devices to declare their queue requirements,
/// and by the transport to construct the actual queues.
#[derive(Clone, Copy, Debug)]
pub struct QueueConfig {
    /// Maximum size of the queue.
    pub size: u16,
}

impl QueueConfig {
    pub const fn new(size: u16) -> Self {
        Self { size }
    }
}

/// A virtqueue combined with its notification eventfd.
/// This is passed to devices during activation.
pub struct DeviceQueue {
    pub queue: Queue,
    pub event: Arc<EventFd>,
}

impl DeviceQueue {
    pub fn new(queue: Queue, event: Arc<EventFd>) -> Self {
        Self { queue, event }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum InterruptType {
    UsedQueue,
    ConfigChange,
}

pub(crate) trait InterruptHandler: Send + Sync {
    fn try_signal(&self, interrupt: InterruptType) -> Result<(), crate::Error>;

    /// Signals used buffers on `queue`. Transports with an interrupt per queue
    /// (MSI-X) raise that queue's; by default it is the device's interrupt.
    fn try_signal_queue(&self, _queue: usize) -> Result<(), crate::Error> {
        self.try_signal(InterruptType::UsedQueue)
    }
}

/// A device's interrupts, with used buffers signalled on one queue.
struct QueueInterrupt {
    inner: Arc<dyn InterruptHandler>,
    queue: usize,
}

impl InterruptHandler for QueueInterrupt {
    fn try_signal(&self, interrupt: InterruptType) -> Result<(), crate::Error> {
        match interrupt {
            InterruptType::UsedQueue => self.inner.try_signal_queue(self.queue),
            other => self.inner.try_signal(other),
        }
    }
}

#[derive(Clone)]
pub struct InterruptTransport(Arc<dyn InterruptHandler>);

impl InterruptTransport {
    pub(crate) fn from_handler(handler: Arc<dyn InterruptHandler>) -> Self {
        Self(handler)
    }

    pub fn try_signal_used_queue(&self) -> Result<(), crate::Error> {
        self.0.try_signal(InterruptType::UsedQueue)
    }

    /// Returns these interrupts with used buffers signalled on `queue` only,
    /// for devices that serve each queue separately.
    pub fn for_queue(&self, queue: usize) -> Self {
        Self(Arc::new(QueueInterrupt {
            inner: self.0.clone(),
            queue,
        }))
    }

    pub fn try_signal_config_change(&self) -> Result<(), crate::Error> {
        self.0.try_signal(InterruptType::ConfigChange)
    }

    pub fn signal_used_queue(&self) {
        if let Err(e) = self.try_signal_used_queue() {
            warn!("Failed to signal used queue: {e:?}");
        }
    }

    pub fn signal_config_change(&self) {
        if let Err(e) = self.try_signal_config_change() {
            warn!("Failed to signal config change: {e:?}");
        }
    }
}

pub(crate) struct VirtioTransportState {
    pub(crate) device: Arc<Mutex<dyn VirtioDevice>>,
    pub(crate) features_select: u32,
    pub(crate) acked_features_select: u32,
    pub(crate) queue_select: u32,
    pub(crate) device_status: u32,
    pub(crate) config_generation: u32,
    mem: GuestMemoryMmap,
    pub(crate) queues: Option<Vec<Queue>>,
    queue_evts: Vec<Arc<EventFd>>,
    pub(crate) queue_config: Vec<QueueConfig>,
    bus_master_gate: Option<Arc<AtomicBool>>,
    // Live queues a paused device handed back, until it resumes.
    paused_queues: Option<Vec<DeviceQueue>>,
}

/// The transport state both virtio transports save in a snapshot.
#[derive(bincode::Encode, bincode::Decode)]
pub(crate) struct SavedTransport {
    features_select: u32,
    acked_features_select: u32,
    queue_select: u32,
    device_status: u32,
    config_generation: u32,
    acked_features: u64,
    queues: Vec<QueueSnapshot>,
    // Opaque device-specific state (see `VirtioDevice::save_state`).
    device: Vec<u8>,
}

impl VirtioTransportState {
    pub(crate) fn new(
        mem: GuestMemoryMmap,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) -> io::Result<Self> {
        let queue_config = device
            .try_lock()
            .expect("Mutex of VirtioDevice should not be locked when creating transport state")
            .queue_config()
            .to_vec();
        let queues = Self::create_queues(&queue_config);
        let queue_evts = Self::create_queue_evts(queue_config.len())?;

        Ok(Self {
            device,
            features_select: 0,
            acked_features_select: 0,
            queue_select: 0,
            device_status: device_status::INIT,
            config_generation: 0,
            mem,
            queues: Some(queues),
            queue_evts,
            queue_config,
            bus_master_gate: None,
            paused_queues: None,
        })
    }

    fn create_queues(queue_config: &[QueueConfig]) -> Vec<Queue> {
        queue_config
            .iter()
            .map(|config| Queue::new(config.size))
            .collect()
    }

    fn create_queue_evts(count: usize) -> io::Result<Vec<Arc<EventFd>>> {
        (0..count)
            .map(|_| EventFd::new(EFD_NONBLOCK).map(Arc::new))
            .collect()
    }

    pub(crate) fn locked_device(&self) -> MutexGuard<'_, dyn VirtioDevice + 'static> {
        self.device.lock().expect("Poisoned device lock")
    }

    pub(crate) fn device(&self) -> Arc<Mutex<dyn VirtioDevice>> {
        self.device.clone()
    }

    pub(crate) fn queue_evts(&self) -> &[Arc<EventFd>] {
        &self.queue_evts
    }

    pub(crate) fn set_bus_master_gate(&mut self, gate: Arc<AtomicBool>) {
        self.bus_master_gate = Some(gate.clone());
        if let Some(queues) = &mut self.queues {
            for queue in queues {
                queue.set_bus_master_gate(gate.clone());
            }
        }
    }

    pub(crate) fn queue_max_size(&self, queue_select: u32) -> u16 {
        self.queue_config
            .get(queue_select as usize)
            .map_or(0, |config| config.size)
    }

    pub(crate) fn with_queue<U, F>(&self, queue_select: u32, default: U, f: F) -> U
    where
        F: FnOnce(&Queue) -> U,
    {
        self.queues
            .as_ref()
            .and_then(|queues| queues.get(queue_select as usize))
            .map_or(default, f)
    }

    pub(crate) fn with_queue_mut<F>(&mut self, queue_select: u32, f: F) -> bool
    where
        F: FnOnce(&mut Queue),
    {
        match self
            .queues
            .as_mut()
            .and_then(|queues| queues.get_mut(queue_select as usize))
        {
            Some(queue) => {
                f(queue);
                true
            }
            None => false,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.features_select = 0;
        self.acked_features_select = 0;
        self.queue_select = 0;
        self.device_status = device_status::INIT;
        // Keep config_generation monotonic and reuse queue eventfds across reset.
        let mut queues = Self::create_queues(&self.queue_config);
        if let Some(gate) = &self.bus_master_gate {
            for queue in &mut queues {
                queue.set_bus_master_gate(gate.clone());
            }
        }
        self.queues = Some(queues);
    }

    pub(crate) fn activate(&mut self, interrupt: InterruptTransport) {
        let Some(queues) = self.queues.take() else {
            return;
        };

        let mut device_queues: Vec<DeviceQueue> = queues
            .into_iter()
            .zip(self.queue_evts.iter().cloned())
            .map(|(queue, event)| DeviceQueue::new(queue, event))
            .collect();

        let mut locked_device = self.locked_device();
        let event_idx_enabled =
            (locked_device.acked_features() & (1 << VIRTIO_RING_F_EVENT_IDX)) != 0;
        for device_queue in &mut device_queues {
            device_queue.queue.set_event_idx(event_idx_enabled);
        }
        locked_device
            .activate(self.mem.clone(), interrupt, device_queues)
            .expect("Failed to activate device");
    }

    /// Stops an activated device's workers and keeps its live queues, so
    /// [`VirtioTransportState::save`] can read them.
    pub(crate) fn pause(&mut self) -> std::result::Result<(), crate::Error> {
        if self.paused_queues.is_some() || !self.locked_device().is_activated() {
            return Ok(());
        }
        let queues = self
            .locked_device()
            .pause()
            .map_err(|e| crate::Error::Snapshot(e.to_string()))?;
        self.paused_queues = Some(queues);
        Ok(())
    }

    pub(crate) fn save(&self) -> std::result::Result<SavedTransport, crate::Error> {
        let queues = if self.locked_device().is_activated() {
            let Some(paused) = &self.paused_queues else {
                return Err(crate::Error::Snapshot(
                    "save before pause; the device's workers still own the queues".into(),
                ));
            };
            paused.iter().map(|dq| dq.queue.snapshot()).collect()
        } else {
            self.queues
                .iter()
                .flatten()
                .map(|queue| queue.snapshot())
                .collect()
        };
        let acked_features = self.locked_device().acked_features();
        let device = self.locked_device().save_state();
        Ok(SavedTransport {
            features_select: self.features_select,
            acked_features_select: self.acked_features_select,
            queue_select: self.queue_select,
            device_status: self.device_status,
            config_generation: self.config_generation,
            acked_features,
            queues,
            device,
        })
    }

    /// Loads saved transport state into a transport that hasn't been activated.
    /// A device the guest had activated keeps its queues aside, stopped, until
    /// [`VirtioTransportState::resume`].
    pub(crate) fn restore(
        &mut self,
        saved: &SavedTransport,
    ) -> std::result::Result<(), crate::Error> {
        if saved.queues.len() != self.queue_config.len() {
            return Err(crate::Error::Snapshot(format!(
                "snapshot has {} queues, device has {}",
                saved.queues.len(),
                self.queue_config.len()
            )));
        }
        let mut queues = Self::create_queues(&self.queue_config);
        for (queue, snapshot) in queues.iter_mut().zip(&saved.queues) {
            queue.restore(snapshot);
            if let Some(gate) = &self.bus_master_gate {
                queue.set_bus_master_gate(gate.clone());
            }
        }
        // Ring addresses come from the snapshot, and workers unwrap their
        // accesses to guest memory, so check them before any worker runs.
        if queues.iter().any(|q| q.ready && !q.is_valid(&self.mem)) {
            return Err(crate::Error::Snapshot(
                "restored queue failed validation".into(),
            ));
        }

        self.features_select = saved.features_select;
        self.acked_features_select = saved.acked_features_select;
        self.queue_select = saved.queue_select;
        self.device_status = saved.device_status;
        self.config_generation = saved.config_generation;
        self.locked_device()
            .set_acked_features(saved.acked_features);
        self.locked_device().restore_state(&saved.device)?;

        if saved.device_status & device_status::DRIVER_OK != 0 {
            self.queues = None;
            self.paused_queues = Some(
                queues
                    .into_iter()
                    .zip(self.queue_evts.iter().cloned())
                    .map(|(queue, event)| DeviceQueue::new(queue, event))
                    .collect(),
            );
        } else {
            self.queues = Some(queues);
        }
        Ok(())
    }

    /// Restarts a device stopped by [`VirtioTransportState::pause`] or loaded
    /// by [`VirtioTransportState::restore`].
    pub(crate) fn resume(
        &mut self,
        interrupt: InterruptTransport,
    ) -> std::result::Result<(), crate::Error> {
        let Some(queues) = self.paused_queues.take() else {
            return Ok(());
        };
        // A descriptor the guest made available but no worker had consumed
        // left no notification behind on a restored transport's new eventfds.
        let waiting: Vec<bool> = queues
            .iter()
            .map(|dq| dq.queue.ready && dq.queue.len(&self.mem) > 0)
            .collect();
        self.locked_device()
            .resume(self.mem.clone(), interrupt, queues)
            .map_err(|e| crate::Error::Snapshot(format!("device resume: {e:?}")))?;
        for (event, _) in self.queue_evts.iter().zip(waiting).filter(|(_, w)| *w) {
            let _ = event.write(1);
        }
        Ok(())
    }

    pub(crate) fn set_device_status(
        &mut self,
        status: u32,
        interrupt: InterruptTransport,
        allow_activation: bool,
    ) -> bool {
        use device_status::*;

        match !self.device_status & status {
            ACKNOWLEDGE if self.device_status == INIT => {
                self.device_status = status;
            }
            DRIVER if self.device_status == ACKNOWLEDGE => {
                self.device_status = status;
            }
            FEATURES_OK if self.device_status == (ACKNOWLEDGE | DRIVER) => {
                self.device_status = status;
            }
            DRIVER_OK if self.device_status == (ACKNOWLEDGE | DRIVER | FEATURES_OK) => {
                self.device_status = status;
                if allow_activation && !self.locked_device().is_activated() {
                    self.activate(interrupt);
                }
            }
            _ if status & FAILED != 0 => {
                self.device_status |= FAILED;
            }
            _ if status == 0 => {
                let device_activated = self.locked_device().is_activated();
                if device_activated {
                    debug!("reset device while it's still in active state");
                }
                if device_activated && !self.locked_device().reset() {
                    self.device_status |= FAILED;
                }

                if self.device_status & FAILED == 0 {
                    self.reset();
                    return true;
                }
            }
            _ => {
                warn!(
                    "invalid virtio driver status transition: 0x{:x} -> 0x{:x}",
                    self.device_status, status
                );
            }
        }

        false
    }
}

/// Enum that indicates if a VirtioDevice is inactive or has been activated
/// and memory attached to it.
pub enum DeviceState {
    Inactive,
    Activated(GuestMemoryMmap, InterruptTransport),
}

impl DeviceState {
    pub fn signal_used_queue(&self) {
        match self {
            Self::Inactive => {
                warn!("DeviceState::signal_used_queue() called, but device is not activated")
            }
            Self::Activated(_, interrupt) => interrupt.signal_used_queue(),
        }
    }
}

impl DeviceState {
    pub fn is_activated(&self) -> bool {
        matches!(self, DeviceState::Activated(..))
    }
}

#[derive(Clone)]
pub struct VirtioShmRegion {
    pub host_addr: u64,
    pub guest_addr: u64,
    pub size: usize,
}

/// Trait for virtio devices to be driven by a virtio transport.
///
/// The lifecycle of a virtio device is to be moved to a virtio transport, which will then query the
/// device. The transport constructs queues based on queue_config() and passes them to the device
/// during activation, transferring ownership. After reset, the transport recreates queues
/// from queue_config() for the next negotiation cycle.
pub trait VirtioDevice: AsAny + Send {
    /// Get the available features offered by device.
    fn avail_features(&self) -> u64;

    /// Get acknowledged features of the driver.
    fn acked_features(&self) -> u64;

    /// Set acknowledged features of the driver.
    /// This function must maintain the following invariant:
    /// - self.avail_features() & self.acked_features() = self.get_acked_features()
    fn set_acked_features(&mut self, acked_features: u64);

    /// The virtio device type.
    fn device_type(&self) -> u32;

    /// Device name used for logging information about the device at the transport layer
    fn device_name(&self) -> &str;

    /// Returns the queue configuration for this device.
    /// The transport uses this to construct the queues during initialization and after reset.
    fn queue_config(&self) -> &[QueueConfig];

    /// Returns the length of the device-specific configuration space when known.
    /// Transports that expose device config through a capability require a length.
    fn config_len(&self) -> Option<u32> {
        None
    }

    /// The set of feature bits shifted by `page * 32`.
    fn avail_features_by_page(&self, page: u32) -> u32 {
        let avail_features = self.avail_features();
        match page {
            // Get the lower 32-bits of the features bitfield.
            0 => avail_features as u32,
            // Get the upper 32-bits of the features bitfield.
            1 => (avail_features >> 32) as u32,
            _ => {
                warn!("Received request for unknown features page.");
                0u32
            }
        }
    }

    /// Acknowledges that this set of features should be enabled.
    fn ack_features_by_page(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => u64::from(value),
            1 => u64::from(value) << 32,
            _ => {
                warn!("Cannot acknowledge unknown features page: {page}");
                0u64
            }
        };

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let avail_features = self.avail_features();
        let unrequested_features = v & !avail_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature: {v:x}");
            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.set_acked_features(self.acked_features() | v);
    }

    /// Reads this device configuration space at `offset`.
    fn read_config(&self, offset: u64, data: &mut [u8]);

    /// Writes to this device configuration space at `offset`.
    fn write_config(&mut self, offset: u64, data: &[u8]);

    /// Performs the formal activation for a device, which can be verified also with `is_activated`.
    /// Ownership of the queues is transferred to the device.
    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult;

    /// Checks if the resources of this device are activated.
    fn is_activated(&self) -> bool;

    /// Optionally deactivates this device. The device should drop its queues.
    /// After reset, the transport will recreate queues from queue_config().
    fn reset(&mut self) -> bool {
        false
    }

    /// Get base and size of the SHM region
    fn shm_region(&self) -> Option<&VirtioShmRegion> {
        None
    }

    /// Stop this device's workers and hand its live queues back for snapshot.
    /// The workers own the running queue indices, so the transport cannot read
    /// them until they stop. The default rejects the snapshot.
    fn pause(&mut self) -> std::result::Result<Vec<DeviceQueue>, PauseError> {
        Err(PauseError::Unsupported(self.device_name().to_string()))
    }

    /// Device state beyond the queues (e.g. the console's open ports, which a
    /// restored guest won't re-announce). Captured after [`VirtioDevice::pause`].
    fn save_state(&self) -> Vec<u8> {
        Vec::new()
    }

    /// Load what [`VirtioDevice::save_state`] wrote, before [`VirtioDevice::resume`].
    fn restore_state(&mut self, _state: &[u8]) -> std::result::Result<(), crate::Error> {
        Ok(())
    }

    /// Restart this device with `queues`, in place of [`VirtioDevice::activate`].
    /// The default re-activates; override when resume differs from a fresh
    /// activation (the console restarts only the ports the guest had open).
    fn resume(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        self.activate(mem, interrupt, queues)
    }
}

/// Why a device could not be quiesced for a snapshot.
#[derive(Debug)]
pub enum PauseError {
    /// The device has no quiesce support, so it cannot be snapshotted.
    Unsupported(String),
    /// The device tried to stop its workers and failed.
    Failed(String),
}

impl fmt::Display for PauseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PauseError::Unsupported(name) => {
                write!(f, "{name} can't be paused for a snapshot")
            }
            PauseError::Failed(e) => write!(f, "pausing failed: {e}"),
        }
    }
}

pub trait VmmExitObserver: Send {
    /// Callback to finish processing or cleanup the device resources
    fn on_vmm_exit(&mut self) {}
}

impl<F: Fn() + Send> VmmExitObserver for F {
    fn on_vmm_exit(&mut self) {
        self()
    }
}

impl std::fmt::Debug for dyn VirtioDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "VirtioDevice type {}", self.device_type())
    }
}
