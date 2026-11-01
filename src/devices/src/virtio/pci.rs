// SPDX-License-Identifier: Apache-2.0

//! Modern virtio-pci transport.

use std::fmt::{Display, Formatter};
use std::io;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::pci::{
    PCI_CONVENTIONAL_CONFIG_SPACE_SIZE, PCI_UNIMPLEMENTED_READ_BYTE, PciBarAccess, PciFunction,
    PciIntxLine, PciMsiVectors, PciQueueNotifications,
};
use utils::eventfd::EventFd;
use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;
use vm_memory::{Address, GuestAddress, GuestMemoryMmap};

use super::device::{InterruptHandler, InterruptType, SavedTransport, VirtioTransportState};
use super::{InterruptTransport, VirtioDevice, device_status};
use crate::snapshot::{SavedState, Snapshottable};

const PCI_VENDOR_ID_VIRTIO: u16 = 0x1af4;
const PCI_DEVICE_ID_VIRTIO_MODERN: u16 = 0x1040;
const PCI_CAPABILITY_ID_VENDOR_SPECIFIC: u8 = 0x09;
const PCI_CAPABILITY_LIST_STATUS: u16 = 1 << 4;
const PCI_STATUS_INTERRUPT: u16 = 1 << 3;
const PCI_COMMAND_MEMORY: u16 = 1 << 1;
const PCI_COMMAND_MASTER: u16 = 1 << 2;
const PCI_COMMAND_INTX_DISABLE: u16 = 1 << 10;
const PCI_INTERRUPT_PIN_INTA: u8 = 1;
const PCI_REVISION_MODERN: u8 = 1;
const PCI_HEADER_TYPE_ENDPOINT: u8 = 0;
const PCI_BAR0_INDEX: u8 = 0;
const PCI_SUBSYSTEM_DEVICE_ID_BASE: u16 = 0x40;
const VIRTIO_PCI_CAPABILITY_LENGTH: u8 = 16;
const VIRTIO_PCI_NOTIFY_CAPABILITY_LENGTH: u8 = 20;
const PCI_CFG_DATA_SIZE: usize = size_of::<u32>();
const BYTE_SIZE: usize = size_of::<u8>();
const WORD_SIZE: usize = size_of::<u16>();
const DWORD_SIZE: usize = size_of::<u32>();
const QWORD_SIZE: usize = size_of::<u64>();
const VIRTIO_QUEUE_READY: u16 = 1;
const QUEUE_ADDRESS_HALF_MASK: u64 = u32::MAX as u64;
const QUEUE_EVENT_SIGNAL: u64 = 1;

const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;
const VIRTIO_PCI_CAP_PCI_CFG: u8 = 5;

const PCI_CONFIG_SIZE: usize = PCI_CONVENTIONAL_CONFIG_SPACE_SIZE;
const PCI_BAR0_OFFSET: usize = pci_config::BAR0;
const PCI_BAR0_SIZE: usize = size_of::<u32>();
const PCI_BAR0_END: usize = PCI_BAR0_OFFSET + PCI_BAR0_SIZE - 1;
const PCI_STATUS_LAST_BYTE: usize = pci_config::STATUS + WORD_SIZE - 1;
const PCI_COMMAND_LAST_BYTE: usize = pci_config::COMMAND + WORD_SIZE - 1;
pub const VIRTIO_PCI_BAR0_SIZE: u64 = 0x8000;
const VIRTIO_PCI_BAR0_ADDRESS_MASK: u32 = !(VIRTIO_PCI_BAR0_SIZE as u32 - 1);
const PCI_BAR_ATTRIBUTE_MASK: u32 = 0x0f;
const PCI_BAR_ADDRESS_MASK: u32 = !PCI_BAR_ATTRIBUTE_MASK;
const PCI_BAR_PROBE_VALUE: u32 = u32::MAX;

const COMMON_CFG_OFFSET: u64 = 0x0000;
const NOTIFY_CFG_OFFSET: u64 = 0x1000;
const NOTIFY_CFG_LEN: u32 = 0x1000;
const NOTIFY_OFF_MULTIPLIER: u32 = 4;
const ISR_CFG_OFFSET: u64 = 0x2000;
const DEVICE_CFG_OFFSET: u64 = 0x3000;
const COMMON_CFG_LEN: u32 = (common_cfg::QUEUE_RESET_OFFSET + size_of::<u16>() as u64) as u32;
const COMMON_CFG_DWORD_SIZE: u64 = size_of::<u32>() as u64;

const VIRTIO_ISR_QUEUE: u8 = 1;
const VIRTIO_ISR_CONFIG: u8 = 2;
const VIRTIO_MSI_NO_VECTOR: u16 = 0xffff;

// The MSI-X capability, with its table and pending bit array in BAR0 after
// the device configuration.
const PCI_CAPABILITY_ID_MSIX: u8 = 0x11;
const MSIX_TABLE_OFFSET: u64 = 0x4000;
const MSIX_PBA_OFFSET: u64 = 0x5000;
const MSIX_ENTRY_SIZE: u64 = 16;
const MSIX_CONTROL_ENABLE: u16 = 1 << 15;
const MSIX_CONTROL_FUNCTION_MASK: u16 = 1 << 14;
const MSIX_VECTOR_CONTROL_MASKED: u32 = 1;

mod msix_cap {
    pub const CONTROL: usize = 0x02;
    pub const TABLE: usize = 0x04;
    pub const PBA: usize = 0x08;
}

mod pci_config {
    pub const VENDOR_ID: usize = 0x00;
    pub const DEVICE_ID: usize = 0x02;
    pub const COMMAND: usize = 0x04;
    pub const STATUS: usize = 0x06;
    pub const REVISION_ID: usize = 0x08;
    pub const HEADER_TYPE: usize = 0x0e;
    pub const BAR0: usize = 0x10;
    pub const SUBSYSTEM_VENDOR_ID: usize = 0x2c;
    pub const SUBSYSTEM_DEVICE_ID: usize = 0x2e;
    pub const CAPABILITY_POINTER: usize = 0x34;
    pub const INTERRUPT_LINE: usize = 0x3c;
    pub const INTERRUPT_PIN: usize = 0x3d;
    pub const CAPABILITIES_START: usize = 0x40;
}

mod vendor_cap {
    pub const VENDOR_SPECIFIC_CAPABILITY_ID: usize = 0x00;
    pub const NEXT: usize = 0x01;
    pub const LENGTH: usize = 0x02;
    pub const CONFIG_TYPE: usize = 0x03;
    pub const BAR: usize = 0x04;
    pub const REGION_ID: usize = 0x05;
    pub const REGION_OFFSET: usize = 0x08;
    pub const REGION_LENGTH: usize = 0x0c;
    pub const NOTIFY_MULTIPLIER: usize = 0x10;
    pub const PCI_CONFIG_DATA: usize = 0x10;
}

mod common_cfg {
    pub const DEVICE_FEATURE_SELECT: u64 = 0x00;
    pub const DEVICE_FEATURE: u64 = 0x04;
    pub const DRIVER_FEATURE_SELECT: u64 = 0x08;
    pub const DRIVER_FEATURE: u64 = 0x0c;
    pub const MSIX_CONFIG: u64 = 0x10;
    pub const NUMBER_OF_QUEUES: u64 = 0x12;
    pub const DEVICE_STATUS: u64 = 0x14;
    pub const CONFIG_GENERATION: u64 = 0x15;
    pub const QUEUE_SELECT: u64 = 0x16;
    pub const QUEUE_SIZE: u64 = 0x18;
    pub const QUEUE_MSIX_VECTOR: u64 = 0x1a;
    pub const QUEUE_ENABLE: u64 = 0x1c;
    pub const QUEUE_NOTIFY_OFFSET: u64 = 0x1e;
    pub const QUEUE_DESCRIPTOR: u64 = 0x20;
    pub const QUEUE_DESCRIPTOR_HIGH: u64 = QUEUE_DESCRIPTOR + super::COMMON_CFG_DWORD_SIZE;
    pub const QUEUE_DRIVER: u64 = 0x28;
    pub const QUEUE_DRIVER_HIGH: u64 = QUEUE_DRIVER + super::COMMON_CFG_DWORD_SIZE;
    pub const QUEUE_DEVICE: u64 = 0x30;
    pub const QUEUE_DEVICE_HIGH: u64 = QUEUE_DEVICE + super::COMMON_CFG_DWORD_SIZE;
    pub const QUEUE_NOTIFY_DATA: u64 = 0x38;
    pub const QUEUE_RESET_OFFSET: u64 = 0x3a;
}

#[derive(Debug)]
pub enum CreatePciTransportError {
    EventFd(io::Error),
    DeviceConfigTooLarge(u32),
    InvalidBarBase(u32),
    MissingVersion1,
    UnknownDeviceConfigLength,
    SharedMemoryNotSupported,
}

impl Display for CreatePciTransportError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EventFd(err) => write!(f, "failed to create queue eventfd: {err}"),
            Self::DeviceConfigTooLarge(size) => {
                write!(
                    f,
                    "virtio device configuration is too large for BAR0: {size}"
                )
            }
            Self::InvalidBarBase(base) => write!(f, "invalid BAR0 base address: 0x{base:x}"),
            Self::MissingVersion1 => {
                write!(
                    f,
                    "modern virtio-pci device does not offer VIRTIO_F_VERSION_1"
                )
            }
            Self::UnknownDeviceConfigLength => {
                write!(
                    f,
                    "virtio device did not report its configuration space length"
                )
            }
            Self::SharedMemoryNotSupported => {
                write!(f, "virtio-pci shared-memory regions are not supported")
            }
        }
    }
}

impl std::error::Error for CreatePciTransportError {}

#[derive(Clone, Copy)]
struct MsixEntry {
    address: u64,
    data: u32,
    masked: bool,
}

/// MSI-X state: the vector table, the pending bits, and the vectors the guest
/// assigned to the configuration and to each queue.
struct MsixState {
    vectors: Arc<dyn PciMsiVectors>,
    enabled: bool,
    function_masked: bool,
    table: Vec<MsixEntry>,
    pending: Vec<bool>,
    config_vector: u16,
    queue_vectors: Vec<u16>,
}

impl MsixState {
    fn new(vectors: Arc<dyn PciMsiVectors>, queues: usize) -> Self {
        let count = usize::from(vectors.count());
        Self {
            vectors,
            enabled: false,
            function_masked: false,
            table: vec![
                MsixEntry {
                    address: 0,
                    data: 0,
                    masked: true,
                };
                count
            ],
            pending: vec![false; count],
            config_vector: VIRTIO_MSI_NO_VECTOR,
            queue_vectors: vec![VIRTIO_MSI_NO_VECTOR; queues],
        }
    }

    fn deliverable(&self, vector: usize) -> bool {
        self.enabled && !self.function_masked && !self.table[vector].masked
    }

    /// Signals `vector`, or marks it pending if it is masked.
    fn deliver(&mut self, vector: u16) -> io::Result<()> {
        let index = usize::from(vector);
        if index >= self.table.len() {
            return Ok(());
        }
        if self.deliverable(index) {
            self.vectors.signal(vector)
        } else {
            self.pending[index] = true;
            Ok(())
        }
    }

    /// If vector `index` is unmasked, routes it to its programmed message and
    /// signals it if it was pending.
    fn sync(&mut self, index: usize) {
        if !self.deliverable(index) {
            return;
        }
        let entry = self.table[index];
        if let Err(err) = self
            .vectors
            .route(index as u16, Some((entry.address, entry.data)))
        {
            warn!("failed to route MSI-X vector {index}: {err}");
        }
        if self.pending[index] {
            self.pending[index] = false;
            if let Err(err) = self.vectors.signal(index as u16) {
                warn!("failed to send MSI-X vector {index}: {err}");
            }
        }
    }

    fn sync_all(&mut self) {
        for index in 0..self.table.len() {
            self.sync(index);
        }
    }

    /// Returns `vector` if the table has it, `VIRTIO_MSI_NO_VECTOR` otherwise.
    fn valid_vector(&self, vector: u16) -> u16 {
        if usize::from(vector) < self.table.len() {
            vector
        } else {
            VIRTIO_MSI_NO_VECTOR
        }
    }
}

struct PciInterruptInner {
    state: Mutex<PciInterruptState>,
    line: Arc<dyn PciIntxLine>,
    msix: Option<Arc<Mutex<MsixState>>>,
    log_target: String,
}

struct PciInterruptState {
    isr: u8,
    intx_disabled: bool,
}

#[derive(Clone)]
struct PciInterrupt(Arc<PciInterruptInner>);

impl PciInterrupt {
    fn new(
        line: Arc<dyn PciIntxLine>,
        msix: Option<Arc<Mutex<MsixState>>>,
        log_target: String,
    ) -> Self {
        Self(Arc::new(PciInterruptInner {
            state: Mutex::new(PciInterruptState {
                isr: 0,
                intx_disabled: false,
            }),
            line,
            msix,
            log_target,
        }))
    }

    /// The MSI-X state, if the guest has enabled MSI-X, which then replaces
    /// INTx.
    fn msix_enabled(&self) -> Option<MutexGuard<'_, MsixState>> {
        let msix = self.0.msix.as_ref()?.lock().unwrap();
        msix.enabled.then_some(msix)
    }

    fn read_isr(&self) -> u8 {
        let mut state = self.0.state.lock().unwrap();
        let isr = state.isr;
        state.isr = 0;
        if isr != 0
            && !state.intx_disabled
            && let Err(err) = self.0.line.set_level(false)
        {
            warn!("failed to deassert virtio-pci INTx: {err}");
        }
        isr
    }

    fn is_pending(&self) -> bool {
        self.0.state.lock().unwrap().isr != 0
    }

    fn reset(&self) {
        let mut state = self.0.state.lock().unwrap();
        if state.isr != 0
            && !state.intx_disabled
            && let Err(err) = self.0.line.set_level(false)
        {
            warn!("failed to deassert virtio-pci INTx during reset: {err}");
        }
        state.isr = 0;
    }

    fn set_intx_disabled(&self, disabled: bool) {
        let mut state = self.0.state.lock().unwrap();
        if state.intx_disabled == disabled {
            return;
        }
        state.intx_disabled = disabled;
        if state.isr != 0
            && let Err(err) = self.0.line.set_level(!disabled)
        {
            warn!("failed to update virtio-pci INTx disable state: {err}");
        }
    }

    fn saved(&self) -> (u8, bool) {
        let state = self.0.state.lock().unwrap();
        (state.isr, state.intx_disabled)
    }

    /// Loads saved interrupt state, asserting INTx if it was asserted.
    fn restore(&self, isr: u8, intx_disabled: bool) {
        let mut state = self.0.state.lock().unwrap();
        state.isr = isr;
        state.intx_disabled = intx_disabled;
        let msix_enabled = self
            .0
            .msix
            .as_ref()
            .is_some_and(|msix| msix.lock().unwrap().enabled);
        if isr != 0
            && !intx_disabled
            && !msix_enabled
            && let Err(err) = self.0.line.set_level(true)
        {
            warn!("failed to assert virtio-pci INTx on restore: {err}");
        }
    }

    fn signal(&self, bit: u8) -> Result<(), crate::Error> {
        let mut state = self.0.state.lock().unwrap();
        let was_pending = state.isr != 0;
        state.isr |= bit;
        if state.intx_disabled || was_pending {
            return Ok(());
        }
        self.0
            .line
            .set_level(true)
            .map_err(crate::Error::FailedSignalingUsedQueue)
    }
}

impl InterruptHandler for PciInterrupt {
    fn try_signal(&self, interrupt: InterruptType) -> Result<(), crate::Error> {
        if let Some(mut msix) = self.msix_enabled() {
            let result = match interrupt {
                InterruptType::UsedQueue => {
                    // The queue isn't known, so signal each vector the queues use, once.
                    let mut vectors = msix.queue_vectors.clone();
                    vectors.sort_unstable();
                    vectors.dedup();
                    vectors
                        .into_iter()
                        .filter(|&vector| vector != VIRTIO_MSI_NO_VECTOR)
                        .try_for_each(|vector| msix.deliver(vector))
                }
                InterruptType::ConfigChange => {
                    let vector = msix.config_vector;
                    msix.deliver(vector)
                }
            };
            return result.map_err(crate::Error::FailedSignalingUsedQueue);
        }
        let (bit, description) = match interrupt {
            InterruptType::UsedQueue => (VIRTIO_ISR_QUEUE, "used queue"),
            InterruptType::ConfigChange => (VIRTIO_ISR_CONFIG, "configuration change"),
        };
        debug!(target: &self.0.log_target, "interrupt: {description}");
        self.signal(bit)
    }

    fn try_signal_queue(&self, queue: usize) -> Result<(), crate::Error> {
        if let Some(mut msix) = self.msix_enabled() {
            let Some(&vector) = msix.queue_vectors.get(queue) else {
                return Ok(());
            };
            return msix
                .deliver(vector)
                .map_err(crate::Error::FailedSignalingUsedQueue);
        }
        self.try_signal(InterruptType::UsedQueue)
    }
}

#[derive(Clone, Copy)]
struct Capability {
    offset: u8,
    len: u8,
    cfg_type: u8,
    bar_offset: u32,
    bar_len: u32,
}

#[derive(Clone, Copy)]
struct PciQueueRegisters {
    size: u16,
    enabled: bool,
    notification_pending: bool,
}

impl PciQueueRegisters {
    fn new(max_size: u16) -> Self {
        Self {
            size: max_size,
            enabled: false,
            notification_pending: false,
        }
    }
}

struct PciConfigSpace([u8; PCI_CONFIG_SIZE]);

impl Default for PciConfigSpace {
    fn default() -> Self {
        Self([0; PCI_CONFIG_SIZE])
    }
}

impl PciConfigSpace {
    fn read_bytes(&self, offset: usize, length: usize) -> Option<&[u8]> {
        self.0.get(offset..offset.checked_add(length)?)
    }

    fn write_bytes(&mut self, offset: usize, data: &[u8]) {
        let end = offset
            .checked_add(data.len())
            .expect("PCI config-space write range overflowed");
        self.0
            .get_mut(offset..end)
            .expect("PCI config-space write is within bounds")
            .copy_from_slice(data);
    }

    fn read_u8(&self, offset: usize) -> Option<u8> {
        self.read_bytes(offset, size_of::<u8>())?.first().copied()
    }

    fn read_u16(&self, offset: usize) -> Option<u16> {
        let bytes = self.read_bytes(offset, size_of::<u16>())?.try_into().ok()?;
        Some(u16::from_le_bytes(bytes))
    }

    fn read_u32(&self, offset: usize) -> Option<u32> {
        let bytes = self.read_bytes(offset, size_of::<u32>())?.try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    fn write_u8(&mut self, offset: usize, value: u8) {
        self.write_bytes(offset, &[value]);
    }

    fn write_u16(&mut self, offset: usize, value: u16) {
        self.write_bytes(offset, &value.to_le_bytes());
    }

    fn write_u32(&mut self, offset: usize, value: u32) {
        self.write_bytes(offset, &value.to_le_bytes());
    }
}

pub struct VirtioPciTransport {
    state: VirtioTransportState,
    config: PciConfigSpace,
    bar_base: u32,
    bar_probe: bool,
    interrupt: PciInterrupt,
    device_interrupt: InterruptTransport,
    capabilities: Vec<Capability>,
    pci_cfg_cap_offset: Option<usize>,
    device_config_len: u32,
    queue_registers: Vec<PciQueueRegisters>,
    bus_master_enabled: Arc<AtomicBool>,
    queue_notifications: Option<Arc<dyn PciQueueNotifications>>,
    queue_notifications_base: Option<u64>,
    msix: Option<Arc<Mutex<MsixState>>>,
    msix_cap_offset: Option<usize>,
}

impl VirtioPciTransport {
    /// With `msix_vectors`, the function offers MSI-X, with a vector for
    /// virtio's configuration and one for each queue. It uses INTx otherwise,
    /// and while the guest leaves MSI-X disabled.
    pub fn new(
        mem: GuestMemoryMmap,
        device: Arc<Mutex<dyn VirtioDevice>>,
        interrupt_line: u8,
        intx_line: Arc<dyn PciIntxLine>,
        bar_base: u32,
        msix_vectors: Option<Arc<dyn PciMsiVectors>>,
    ) -> Result<Self, CreatePciTransportError> {
        let (device_type, device_name, avail_features, device_config_len, has_shm) = {
            let locked = device.try_lock().expect(
                "Mutex of VirtioDevice should not be locked when creating virtio-pci transport",
            );
            (
                locked.device_type(),
                locked.device_name().to_string(),
                locked.avail_features(),
                locked.config_len(),
                locked.shm_region().is_some(),
            )
        };

        if avail_features & (1u64 << VIRTIO_F_VERSION_1) == 0 {
            return Err(CreatePciTransportError::MissingVersion1);
        }
        if has_shm {
            return Err(CreatePciTransportError::SharedMemoryNotSupported);
        }
        let device_config_len =
            device_config_len.ok_or(CreatePciTransportError::UnknownDeviceConfigLength)?;
        let device_config_end = if msix_vectors.is_some() {
            MSIX_TABLE_OFFSET
        } else {
            VIRTIO_PCI_BAR0_SIZE
        };
        if u64::from(device_config_len) > device_config_end - DEVICE_CFG_OFFSET {
            return Err(CreatePciTransportError::DeviceConfigTooLarge(
                device_config_len,
            ));
        }
        if u64::from(bar_base) % VIRTIO_PCI_BAR0_SIZE != 0
            || u64::from(bar_base) + VIRTIO_PCI_BAR0_SIZE > (1u64 << 32)
        {
            return Err(CreatePciTransportError::InvalidBarBase(bar_base));
        }

        let mut state =
            VirtioTransportState::new(mem, device).map_err(CreatePciTransportError::EventFd)?;

        for queue_index in 0..state.queue_config.len() {
            let max_size = state.queue_max_size(queue_index as u32);
            state.with_queue_mut(queue_index as u32, |queue| queue.size = max_size);
        }

        let bus_master_enabled = Arc::new(AtomicBool::new(false));
        state.set_bus_master_gate(bus_master_enabled.clone());
        let queue_registers = state
            .queue_config
            .iter()
            .map(|queue| PciQueueRegisters::new(queue.size))
            .collect();
        let msix = msix_vectors.map(|vectors| {
            Arc::new(Mutex::new(MsixState::new(
                vectors,
                state.queue_config.len(),
            )))
        });
        let msix_count = msix
            .as_ref()
            .map(|msix| msix.lock().unwrap().table.len() as u16);
        let interrupt = PciInterrupt::new(
            intx_line,
            msix.clone(),
            format!("{}[{device_name}]", module_path!()),
        );
        let device_interrupt = InterruptTransport::from_handler(Arc::new(interrupt.clone()));
        let (config, capabilities, pci_cfg_cap_offset, msix_cap_offset) =
            Self::build_config(device_type, device_config_len, interrupt_line, msix_count);

        Ok(Self {
            state,
            config,
            bar_base,
            bar_probe: false,
            interrupt,
            device_interrupt,
            capabilities,
            pci_cfg_cap_offset,
            device_config_len,
            queue_registers,
            bus_master_enabled,
            queue_notifications: None,
            queue_notifications_base: None,
            msix,
            msix_cap_offset,
        })
    }

    /// Each queue's eventfd and its notify offset in BAR0.
    pub fn queue_notify_events(&self) -> Vec<(u64, Arc<EventFd>)> {
        self.state
            .queue_evts()
            .iter()
            .enumerate()
            .map(|(i, event)| {
                (
                    NOTIFY_CFG_OFFSET + i as u64 * u64::from(NOTIFY_OFF_MULTIPLIER),
                    event.clone(),
                )
            })
            .collect()
    }

    /// Hands queue notifications to `notifications` while BAR0 is mapped and
    /// memory decoding and bus mastering are on. Otherwise they go through the
    /// transport, which keeps them pending until bus mastering is on.
    pub fn set_queue_notifications(&mut self, notifications: Arc<dyn PciQueueNotifications>) {
        self.queue_notifications = Some(notifications);
        self.update_queue_notifications();
    }

    fn update_queue_notifications(&mut self) {
        let Some(notifications) = &self.queue_notifications else {
            return;
        };
        let command = self
            .config
            .read_u16(pci_config::COMMAND)
            .expect("PCI command register fits in configuration space");
        let base = (self.bar_base != 0
            && command & PCI_COMMAND_MEMORY != 0
            && self.bus_master_enabled.load(Ordering::Acquire))
        .then_some(u64::from(self.bar_base));
        if base == self.queue_notifications_base {
            return;
        }
        match notifications.relocate(self.queue_notifications_base, base) {
            Ok(()) => self.queue_notifications_base = base,
            Err(err) => warn!(
                "virtio-pci queue notifications did not move from {:x?} to {base:x?}: {err}",
                self.queue_notifications_base
            ),
        }
    }

    pub fn device(&self) -> Arc<Mutex<dyn VirtioDevice>> {
        self.state.device()
    }

    fn build_config(
        device_type: u32,
        device_config_len: u32,
        interrupt_line: u8,
        msix_count: Option<u16>,
    ) -> (
        PciConfigSpace,
        Vec<Capability>,
        Option<usize>,
        Option<usize>,
    ) {
        let mut config = PciConfigSpace::default();
        let mut capabilities = vec![
            Capability {
                offset: 0,
                len: VIRTIO_PCI_CAPABILITY_LENGTH,
                cfg_type: VIRTIO_PCI_CAP_COMMON_CFG,
                bar_offset: COMMON_CFG_OFFSET as u32,
                bar_len: COMMON_CFG_LEN,
            },
            Capability {
                offset: 0,
                len: VIRTIO_PCI_NOTIFY_CAPABILITY_LENGTH,
                cfg_type: VIRTIO_PCI_CAP_NOTIFY_CFG,
                bar_offset: NOTIFY_CFG_OFFSET as u32,
                bar_len: NOTIFY_CFG_LEN,
            },
            Capability {
                offset: 0,
                len: VIRTIO_PCI_CAPABILITY_LENGTH,
                cfg_type: VIRTIO_PCI_CAP_ISR_CFG,
                bar_offset: ISR_CFG_OFFSET as u32,
                bar_len: 1,
            },
        ];
        if device_config_len != 0 {
            capabilities.push(Capability {
                offset: 0,
                len: VIRTIO_PCI_CAPABILITY_LENGTH,
                cfg_type: VIRTIO_PCI_CAP_DEVICE_CFG,
                bar_offset: DEVICE_CFG_OFFSET as u32,
                bar_len: device_config_len,
            });
        }
        capabilities.push(Capability {
            offset: 0,
            len: VIRTIO_PCI_NOTIFY_CAPABILITY_LENGTH,
            cfg_type: VIRTIO_PCI_CAP_PCI_CFG,
            bar_offset: 0,
            bar_len: 0,
        });

        let mut next_offset = pci_config::CAPABILITIES_START;
        for capability in &mut capabilities {
            capability.offset = next_offset as u8;
            next_offset += usize::from(capability.len);
        }

        let device_id = PCI_DEVICE_ID_VIRTIO_MODERN.wrapping_add(device_type as u16);
        config.write_u16(pci_config::VENDOR_ID, PCI_VENDOR_ID_VIRTIO);
        config.write_u16(pci_config::DEVICE_ID, device_id);
        config.write_u16(pci_config::COMMAND, PCI_COMMAND_MEMORY);
        config.write_u16(pci_config::STATUS, PCI_CAPABILITY_LIST_STATUS);
        config.write_u8(pci_config::REVISION_ID, PCI_REVISION_MODERN);
        config.write_u8(pci_config::HEADER_TYPE, PCI_HEADER_TYPE_ENDPOINT);
        config.write_u16(pci_config::SUBSYSTEM_VENDOR_ID, PCI_VENDOR_ID_VIRTIO);
        config.write_u16(
            pci_config::SUBSYSTEM_DEVICE_ID,
            PCI_SUBSYSTEM_DEVICE_ID_BASE.wrapping_add(device_type as u16),
        );
        config.write_u8(
            pci_config::CAPABILITY_POINTER,
            capabilities
                .first()
                .map_or(0, |capability| capability.offset),
        );
        config.write_u8(pci_config::INTERRUPT_LINE, interrupt_line);
        config.write_u8(pci_config::INTERRUPT_PIN, PCI_INTERRUPT_PIN_INTA);

        let mut pci_cfg_cap_offset = None;
        for (index, capability) in capabilities.iter().enumerate() {
            let offset = usize::from(capability.offset);
            let next = capabilities
                .get(index + 1)
                .map_or(0, |next_capability| next_capability.offset);
            config.write_u8(
                offset + vendor_cap::VENDOR_SPECIFIC_CAPABILITY_ID,
                PCI_CAPABILITY_ID_VENDOR_SPECIFIC,
            );
            config.write_u8(offset + vendor_cap::NEXT, next);
            config.write_u8(offset + vendor_cap::LENGTH, capability.len);
            config.write_u8(offset + vendor_cap::CONFIG_TYPE, capability.cfg_type);
            config.write_u8(offset + vendor_cap::BAR, PCI_BAR0_INDEX);
            config.write_u8(offset + vendor_cap::REGION_ID, 0);
            config.write_u32(offset + vendor_cap::REGION_OFFSET, capability.bar_offset);
            config.write_u32(offset + vendor_cap::REGION_LENGTH, capability.bar_len);

            if capability.cfg_type == VIRTIO_PCI_CAP_NOTIFY_CFG {
                config.write_u32(
                    offset + vendor_cap::NOTIFY_MULTIPLIER,
                    NOTIFY_OFF_MULTIPLIER,
                );
            }
            if capability.cfg_type == VIRTIO_PCI_CAP_PCI_CFG {
                config.write_u32(offset + vendor_cap::REGION_LENGTH, PCI_CFG_DATA_SIZE as u32);
                pci_cfg_cap_offset = Some(offset);
            }
        }

        // The MSI-X capability goes last, after the vendor capabilities.
        let mut msix_cap_offset = None;
        if let Some(count) = msix_count {
            let offset = next_offset;
            if let Some(last) = capabilities.last() {
                config.write_u8(usize::from(last.offset) + vendor_cap::NEXT, offset as u8);
            }
            config.write_u8(offset, PCI_CAPABILITY_ID_MSIX);
            config.write_u8(offset + vendor_cap::NEXT, 0);
            config.write_u16(offset + msix_cap::CONTROL, count - 1);
            config.write_u32(
                offset + msix_cap::TABLE,
                MSIX_TABLE_OFFSET as u32 | u32::from(PCI_BAR0_INDEX),
            );
            config.write_u32(
                offset + msix_cap::PBA,
                MSIX_PBA_OFFSET as u32 | u32::from(PCI_BAR0_INDEX),
            );
            msix_cap_offset = Some(offset);
        }

        (config, capabilities, pci_cfg_cap_offset, msix_cap_offset)
    }

    fn read_msix_table(&self, offset: u64, data: &mut [u8]) {
        let msix = self.msix.as_ref().unwrap().lock().unwrap();
        let index = (offset / MSIX_ENTRY_SIZE) as usize;
        let field = offset % MSIX_ENTRY_SIZE;
        let Some(entry) = msix.table.get(index) else {
            data.fill(0);
            return;
        };
        let value: u32 = match field {
            0 => entry.address as u32,
            4 => (entry.address >> 32) as u32,
            8 => entry.data,
            12 if entry.masked => MSIX_VECTOR_CONTROL_MASKED,
            _ => 0,
        };
        match data.len() {
            DWORD_SIZE => data.copy_from_slice(&value.to_le_bytes()),
            QWORD_SIZE if field == 0 || field == 8 => {
                let high: u32 = if field == 0 {
                    (entry.address >> 32) as u32
                } else if entry.masked {
                    MSIX_VECTOR_CONTROL_MASKED
                } else {
                    0
                };
                data.copy_from_slice(&(u64::from(value) | (u64::from(high) << 32)).to_le_bytes());
            }
            _ => data.fill(0),
        }
    }

    fn write_msix_table(&mut self, offset: u64, data: &[u8]) {
        let mut msix = self.msix.as_ref().unwrap().lock().unwrap();
        let index = (offset / MSIX_ENTRY_SIZE) as usize;
        let field = offset % MSIX_ENTRY_SIZE;
        if index >= msix.table.len() {
            return;
        }
        let mut words: Vec<(u64, u32)> = Vec::new();
        match data.len() {
            DWORD_SIZE => words.push((field, u32::from_le_bytes(data.try_into().unwrap()))),
            QWORD_SIZE => {
                let value = u64::from_le_bytes(data.try_into().unwrap());
                words.push((field, value as u32));
                words.push((field + 4, (value >> 32) as u32));
            }
            _ => return,
        }
        for (field, value) in words {
            let entry = &mut msix.table[index];
            match field {
                0 => entry.address = (entry.address & !0xffff_ffff) | u64::from(value),
                4 => entry.address = (entry.address & 0xffff_ffff) | (u64::from(value) << 32),
                8 => entry.data = value,
                12 => entry.masked = value & MSIX_VECTOR_CONTROL_MASKED != 0,
                _ => {}
            }
        }
        msix.sync(index);
    }

    fn read_msix_pba(&self, offset: u64, data: &mut [u8]) {
        let msix = self.msix.as_ref().unwrap().lock().unwrap();
        for (i, byte) in data.iter_mut().enumerate() {
            let first = (offset as usize + i) * 8;
            *byte = (0..8)
                .filter(|bit| msix.pending.get(first + bit).copied().unwrap_or(false))
                .fold(0u8, |acc, bit| acc | (1 << bit));
        }
    }

    fn msix_table_len(&self) -> u64 {
        self.msix.as_ref().map_or(0, |msix| {
            msix.lock().unwrap().table.len() as u64 * MSIX_ENTRY_SIZE
        })
    }

    fn msix_pba_len(&self) -> u64 {
        self.msix.as_ref().map_or(0, |msix| {
            (msix.lock().unwrap().table.len() as u64).div_ceil(64) * 8
        })
    }

    fn config_status(&self) -> u16 {
        let mut status = self
            .config
            .read_u16(pci_config::STATUS)
            .expect("PCI status register fits in configuration space")
            & !PCI_STATUS_INTERRUPT;
        if self.interrupt.is_pending() {
            status |= PCI_STATUS_INTERRUPT;
        }
        status
    }

    fn bar0_value(&self) -> u32 {
        if self.bar_probe {
            (!(VIRTIO_PCI_BAR0_SIZE as u32 - 1)) & PCI_BAR_ADDRESS_MASK
        } else {
            self.bar_base
        }
    }

    fn config_byte(&self, offset: usize) -> u8 {
        match offset {
            pci_config::STATUS..=PCI_STATUS_LAST_BYTE => self
                .config_status()
                .to_le_bytes()
                .get(offset - pci_config::STATUS)
                .copied()
                .unwrap_or(PCI_UNIMPLEMENTED_READ_BYTE),
            PCI_BAR0_OFFSET..=PCI_BAR0_END => self
                .bar0_value()
                .to_le_bytes()
                .get(offset - PCI_BAR0_OFFSET)
                .copied()
                .unwrap_or(PCI_UNIMPLEMENTED_READ_BYTE),
            _ => self
                .config
                .read_u8(offset)
                .unwrap_or(PCI_UNIMPLEMENTED_READ_BYTE),
        }
    }

    fn pci_cfg_selection(&self) -> Option<(u8, u32, usize)> {
        let offset = self.pci_cfg_cap_offset?;
        let bar = self.config.read_u8(offset + vendor_cap::BAR)?;
        let bar_offset = self.config.read_u32(offset + vendor_cap::REGION_OFFSET)?;
        let length = self.config.read_u32(offset + vendor_cap::REGION_LENGTH)? as usize;
        if bar != PCI_BAR0_INDEX
            || !matches!(length, BYTE_SIZE | WORD_SIZE | DWORD_SIZE)
            || !(bar_offset as usize).is_multiple_of(length)
        {
            return None;
        }
        let end = bar_offset.checked_add(length as u32)?;
        if !self.capabilities.iter().any(|capability| {
            capability.cfg_type != VIRTIO_PCI_CAP_PCI_CFG
                && bar_offset >= capability.bar_offset
                && capability
                    .bar_offset
                    .checked_add(capability.bar_len)
                    .is_some_and(|capability_end| end <= capability_end)
        }) {
            return None;
        }
        Some((bar, bar_offset, length))
    }

    fn read_bar_region(&mut self, offset: u64, data: &mut [u8]) -> PciBarAccess {
        if self.msix.is_some()
            && offset >= MSIX_TABLE_OFFSET
            && offset + data.len() as u64 <= MSIX_TABLE_OFFSET + self.msix_table_len()
        {
            self.read_msix_table(offset - MSIX_TABLE_OFFSET, data);
            return PciBarAccess::Handled;
        }
        if self.msix.is_some()
            && offset >= MSIX_PBA_OFFSET
            && offset + data.len() as u64 <= MSIX_PBA_OFFSET + self.msix_pba_len()
        {
            self.read_msix_pba(offset - MSIX_PBA_OFFSET, data);
            return PciBarAccess::Handled;
        }
        if offset + data.len() as u64 <= u64::from(COMMON_CFG_LEN) {
            self.read_common_config(offset, data);
            return PciBarAccess::Handled;
        }
        if offset >= NOTIFY_CFG_OFFSET
            && offset + data.len() as u64 <= NOTIFY_CFG_OFFSET + u64::from(NOTIFY_CFG_LEN)
        {
            data.fill(0);
            return PciBarAccess::Handled;
        }
        if offset == ISR_CFG_OFFSET && data.len() == BYTE_SIZE {
            data.copy_from_slice(&[self.interrupt.read_isr()]);
            return PciBarAccess::Handled;
        }
        if offset >= DEVICE_CFG_OFFSET
            && offset + data.len() as u64 <= DEVICE_CFG_OFFSET + u64::from(self.device_config_len)
        {
            if data.is_empty() {
                return PciBarAccess::Handled;
            }
            self.state
                .locked_device()
                .read_config(offset - DEVICE_CFG_OFFSET, data);
            return PciBarAccess::Handled;
        }
        data.fill(PCI_UNIMPLEMENTED_READ_BYTE);
        PciBarAccess::Unhandled
    }

    fn write_bar_region(&mut self, offset: u64, data: &[u8]) -> PciBarAccess {
        if self.msix.is_some()
            && offset >= MSIX_TABLE_OFFSET
            && offset + data.len() as u64 <= MSIX_TABLE_OFFSET + self.msix_table_len()
        {
            self.write_msix_table(offset - MSIX_TABLE_OFFSET, data);
            return PciBarAccess::Handled;
        }
        if self.msix.is_some()
            && offset >= MSIX_PBA_OFFSET
            && offset < MSIX_PBA_OFFSET + self.msix_pba_len()
        {
            return PciBarAccess::Handled;
        }
        if offset + data.len() as u64 <= u64::from(COMMON_CFG_LEN) {
            self.write_common_config(offset, data);
            return PciBarAccess::Handled;
        }
        if offset >= NOTIFY_CFG_OFFSET && offset < NOTIFY_CFG_OFFSET + u64::from(NOTIFY_CFG_LEN) {
            self.notify_queue(offset, data);
            return PciBarAccess::Handled;
        }
        if offset >= DEVICE_CFG_OFFSET
            && offset + data.len() as u64 <= DEVICE_CFG_OFFSET + u64::from(self.device_config_len)
        {
            if self.state.device_status & (device_status::DRIVER | device_status::FAILED)
                == device_status::DRIVER
            {
                self.state
                    .locked_device()
                    .write_config(offset - DEVICE_CFG_OFFSET, data);
            }
            return PciBarAccess::Handled;
        }
        PciBarAccess::Unhandled
    }

    fn read_common_config(&mut self, offset: u64, data: &mut [u8]) {
        let queue_select = self.state.queue_select;
        match (offset, data.len()) {
            (common_cfg::DEVICE_FEATURE_SELECT, DWORD_SIZE) => {
                data.copy_from_slice(&self.state.features_select.to_le_bytes());
            }
            (common_cfg::DEVICE_FEATURE, DWORD_SIZE) => {
                let value = self
                    .state
                    .locked_device()
                    .avail_features_by_page(self.state.features_select);
                data.copy_from_slice(&value.to_le_bytes());
            }
            (common_cfg::DRIVER_FEATURE_SELECT, DWORD_SIZE) => {
                data.copy_from_slice(&self.state.acked_features_select.to_le_bytes());
            }
            (common_cfg::DRIVER_FEATURE, DWORD_SIZE) => {
                let page = self.state.acked_features_select;
                let feature_words = u64::BITS / u32::BITS;
                let features = if page < feature_words {
                    (self.state.locked_device().acked_features() >> (page * u32::BITS)) as u32
                } else {
                    0
                };
                data.copy_from_slice(&features.to_le_bytes());
            }
            (common_cfg::MSIX_CONFIG, WORD_SIZE) => {
                let vector = self.msix.as_ref().map_or(VIRTIO_MSI_NO_VECTOR, |msix| {
                    msix.lock().unwrap().config_vector
                });
                data.copy_from_slice(&vector.to_le_bytes());
            }
            (common_cfg::NUMBER_OF_QUEUES, WORD_SIZE) => {
                data.copy_from_slice(&(self.state.queue_config.len() as u16).to_le_bytes());
            }
            (common_cfg::DEVICE_STATUS, BYTE_SIZE) => {
                data.copy_from_slice(&[self.state.device_status as u8]);
            }
            (common_cfg::CONFIG_GENERATION, BYTE_SIZE) => {
                data.copy_from_slice(&[self.state.config_generation as u8]);
            }
            (common_cfg::QUEUE_SELECT, WORD_SIZE) => {
                data.copy_from_slice(&(queue_select as u16).to_le_bytes());
            }
            (common_cfg::QUEUE_SIZE, WORD_SIZE) => {
                let size = self
                    .queue_registers
                    .get(queue_select as usize)
                    .map_or(0, |registers| registers.size);
                data.copy_from_slice(&size.to_le_bytes());
            }
            (common_cfg::QUEUE_MSIX_VECTOR, WORD_SIZE) => {
                let vector = self.msix.as_ref().map_or(VIRTIO_MSI_NO_VECTOR, |msix| {
                    msix.lock()
                        .unwrap()
                        .queue_vectors
                        .get(queue_select as usize)
                        .copied()
                        .unwrap_or(VIRTIO_MSI_NO_VECTOR)
                });
                data.copy_from_slice(&vector.to_le_bytes());
            }
            (common_cfg::QUEUE_ENABLE, WORD_SIZE) => {
                let enabled = self
                    .queue_registers
                    .get(queue_select as usize)
                    .is_some_and(|registers| registers.enabled);
                let value = if enabled { VIRTIO_QUEUE_READY } else { 0 };
                data.copy_from_slice(&value.to_le_bytes());
            }
            (common_cfg::QUEUE_NOTIFY_OFFSET, WORD_SIZE) => {
                let notify_offset = if self.state.queue_max_size(queue_select) == 0 {
                    0
                } else {
                    queue_select as u16
                };
                data.copy_from_slice(&notify_offset.to_le_bytes());
            }
            (
                common_cfg::QUEUE_DESCRIPTOR
                | common_cfg::QUEUE_DESCRIPTOR_HIGH
                | common_cfg::QUEUE_DRIVER
                | common_cfg::QUEUE_DRIVER_HIGH
                | common_cfg::QUEUE_DEVICE
                | common_cfg::QUEUE_DEVICE_HIGH,
                DWORD_SIZE,
            ) => {
                let (base, address) = self.queue_address(offset, queue_select);
                let word = address
                    .map(|address| address.wrapping_shr(((offset - base) as u32) * u8::BITS) as u32)
                    .unwrap_or(0);
                data.copy_from_slice(&word.to_le_bytes());
            }
            (
                common_cfg::QUEUE_DESCRIPTOR | common_cfg::QUEUE_DRIVER | common_cfg::QUEUE_DEVICE,
                QWORD_SIZE,
            ) => {
                let (_, address) = self.queue_address(offset, queue_select);
                data.copy_from_slice(&address.unwrap_or(0).to_le_bytes());
            }
            (common_cfg::QUEUE_NOTIFY_DATA | common_cfg::QUEUE_RESET_OFFSET, WORD_SIZE) => {
                data.copy_from_slice(&0u16.to_le_bytes());
            }
            _ => data.fill(PCI_UNIMPLEMENTED_READ_BYTE),
        }
    }

    fn reset_queue_registers(&mut self) {
        for queue_index in 0..self.queue_registers.len() {
            let max_size = self.state.queue_max_size(queue_index as u32);
            self.queue_registers[queue_index] = PciQueueRegisters::new(max_size);
            self.state
                .with_queue_mut(queue_index as u32, |queue| queue.size = max_size);
        }
    }

    fn queue_address(&self, offset: u64, queue_select: u32) -> (u64, Option<u64>) {
        let base = match offset {
            common_cfg::QUEUE_DESCRIPTOR | common_cfg::QUEUE_DESCRIPTOR_HIGH => {
                common_cfg::QUEUE_DESCRIPTOR
            }
            common_cfg::QUEUE_DRIVER | common_cfg::QUEUE_DRIVER_HIGH => common_cfg::QUEUE_DRIVER,
            common_cfg::QUEUE_DEVICE | common_cfg::QUEUE_DEVICE_HIGH => common_cfg::QUEUE_DEVICE,
            _ => offset,
        };
        let address = self.state.with_queue(queue_select, None, |queue| {
            Some(match base {
                common_cfg::QUEUE_DESCRIPTOR => queue.desc_table.raw_value(),
                common_cfg::QUEUE_DRIVER => queue.avail_ring.raw_value(),
                common_cfg::QUEUE_DEVICE => queue.used_ring.raw_value(),
                _ => 0,
            })
        });
        (base, address)
    }

    fn write_common_config(&mut self, offset: u64, data: &[u8]) {
        if offset == common_cfg::DEVICE_STATUS && data.len() == BYTE_SIZE {
            let status = u32::from(u8::from_le_bytes(data.try_into().unwrap()));
            let was_activated = self.state.locked_device().is_activated();
            if self.state.set_device_status(
                status,
                self.device_interrupt.clone(),
                self.bus_master_enabled.load(Ordering::Acquire),
            ) {
                self.interrupt.reset();
                self.reset_queue_registers();
                if let Some(msix) = &self.msix {
                    let mut msix = msix.lock().unwrap();
                    msix.config_vector = VIRTIO_MSI_NO_VECTOR;
                    msix.queue_vectors.fill(VIRTIO_MSI_NO_VECTOR);
                }
            } else if !was_activated && self.state.locked_device().is_activated() {
                self.replay_pending_queue_notifications();
            }
            return;
        }

        let queue_select = self.state.queue_select;
        match (offset, data.len()) {
            (common_cfg::DEVICE_FEATURE_SELECT, DWORD_SIZE) => {
                self.state.features_select = u32::from_le_bytes(data.try_into().unwrap())
            }
            (common_cfg::DRIVER_FEATURE_SELECT, DWORD_SIZE) => {
                self.state.acked_features_select = u32::from_le_bytes(data.try_into().unwrap())
            }
            (common_cfg::DRIVER_FEATURE, DWORD_SIZE)
                if self.state.device_status
                    & (device_status::DRIVER
                        | device_status::FEATURES_OK
                        | device_status::FAILED)
                    == device_status::DRIVER =>
            {
                self.state.locked_device().ack_features_by_page(
                    self.state.acked_features_select,
                    u32::from_le_bytes(data.try_into().unwrap()),
                );
            }
            (common_cfg::QUEUE_SELECT, WORD_SIZE) => {
                self.state.queue_select = u16::from_le_bytes(data.try_into().unwrap()) as u32
            }
            (common_cfg::MSIX_CONFIG, WORD_SIZE) => {
                if let Some(msix) = &self.msix {
                    let mut msix = msix.lock().unwrap();
                    msix.config_vector =
                        msix.valid_vector(u16::from_le_bytes(data.try_into().unwrap()));
                }
            }
            (common_cfg::QUEUE_MSIX_VECTOR, WORD_SIZE) => {
                if let Some(msix) = &self.msix {
                    let mut msix = msix.lock().unwrap();
                    let vector = msix.valid_vector(u16::from_le_bytes(data.try_into().unwrap()));
                    if let Some(slot) = msix.queue_vectors.get_mut(queue_select as usize) {
                        *slot = vector;
                    }
                }
            }
            (common_cfg::QUEUE_SIZE, WORD_SIZE) if self.can_configure_queue(queue_select) => {
                let size = u16::from_le_bytes(data.try_into().unwrap());
                if self
                    .state
                    .with_queue_mut(queue_select, |queue| queue.size = size)
                    && let Some(registers) = self.queue_registers.get_mut(queue_select as usize)
                {
                    registers.size = size;
                }
            }
            (common_cfg::QUEUE_ENABLE, WORD_SIZE)
                if u16::from_le_bytes(data.try_into().unwrap()) == VIRTIO_QUEUE_READY
                    && self.can_configure_queue(queue_select) =>
            {
                if self
                    .state
                    .with_queue_mut(queue_select, |queue| queue.ready = true)
                    && let Some(registers) = self.queue_registers.get_mut(queue_select as usize)
                {
                    registers.enabled = true;
                }
            }
            (
                common_cfg::QUEUE_DESCRIPTOR
                | common_cfg::QUEUE_DESCRIPTOR_HIGH
                | common_cfg::QUEUE_DRIVER
                | common_cfg::QUEUE_DRIVER_HIGH
                | common_cfg::QUEUE_DEVICE
                | common_cfg::QUEUE_DEVICE_HIGH,
                DWORD_SIZE,
            ) => {
                let value = u32::from_le_bytes(data.try_into().unwrap());
                self.write_queue_address(offset, queue_select, value);
            }
            (
                common_cfg::QUEUE_DESCRIPTOR | common_cfg::QUEUE_DRIVER | common_cfg::QUEUE_DEVICE,
                QWORD_SIZE,
            ) => {
                let value = u64::from_le_bytes(data.try_into().unwrap());
                self.write_queue_address_full(offset, queue_select, value);
            }
            _ => {}
        }
    }

    fn can_configure_queue(&self, queue_select: u32) -> bool {
        self.state.device_status & (device_status::FEATURES_OK | device_status::FAILED)
            == device_status::FEATURES_OK
            && !self
                .state
                .with_queue(queue_select, false, |queue| queue.ready)
    }

    fn write_queue_address(&mut self, offset: u64, queue_select: u32, value: u32) {
        let base = match offset {
            common_cfg::QUEUE_DESCRIPTOR | common_cfg::QUEUE_DESCRIPTOR_HIGH => {
                common_cfg::QUEUE_DESCRIPTOR
            }
            common_cfg::QUEUE_DRIVER | common_cfg::QUEUE_DRIVER_HIGH => common_cfg::QUEUE_DRIVER,
            common_cfg::QUEUE_DEVICE | common_cfg::QUEUE_DEVICE_HIGH => common_cfg::QUEUE_DEVICE,
            _ => return,
        };
        let shift = ((offset - base) as u32) * u8::BITS;
        if self.can_configure_queue(queue_select) {
            self.state.with_queue_mut(queue_select, |queue| {
                let address = match base {
                    common_cfg::QUEUE_DESCRIPTOR => &mut queue.desc_table,
                    common_cfg::QUEUE_DRIVER => &mut queue.avail_ring,
                    _ => &mut queue.used_ring,
                };
                address.0 =
                    (address.0 & !(QUEUE_ADDRESS_HALF_MASK << shift)) | (u64::from(value) << shift);
            });
        }
    }

    fn write_queue_address_full(&mut self, offset: u64, queue_select: u32, value: u64) {
        if !self.can_configure_queue(queue_select) {
            return;
        }
        self.state
            .with_queue_mut(queue_select, |queue| match offset {
                common_cfg::QUEUE_DESCRIPTOR => queue.desc_table = GuestAddress(value),
                common_cfg::QUEUE_DRIVER => queue.avail_ring = GuestAddress(value),
                common_cfg::QUEUE_DEVICE => queue.used_ring = GuestAddress(value),
                _ => {}
            });
    }

    fn notify_queue(&mut self, offset: u64, data: &[u8]) {
        let relative = offset - NOTIFY_CFG_OFFSET;
        if data.len() != WORD_SIZE || !relative.is_multiple_of(u64::from(NOTIFY_OFF_MULTIPLIER)) {
            warn!("invalid virtio-pci queue notification at 0x{offset:x}");
            return;
        }
        let queue_index = (relative / u64::from(NOTIFY_OFF_MULTIPLIER)) as usize;
        let Some(registers) = self.queue_registers.get_mut(queue_index) else {
            return;
        };
        if !self.bus_master_enabled.load(Ordering::Acquire) {
            registers.notification_pending = true;
            return;
        }
        if let Some(event) = self.state.queue_evts().get(queue_index)
            && let Err(err) = event.write(QUEUE_EVENT_SIGNAL)
        {
            warn!("failed to notify virtio-pci queue {queue_index}: {err}");
        }
    }

    fn activate_if_ready(&mut self) {
        if !self.bus_master_enabled.load(Ordering::Acquire)
            || self.state.device_status & device_status::DRIVER_OK == 0
        {
            return;
        }

        if !self.state.locked_device().is_activated() {
            self.state.activate(self.device_interrupt.clone());
        }
        self.replay_pending_queue_notifications();
    }

    fn replay_pending_queue_notifications(&mut self) {
        if !self.bus_master_enabled.load(Ordering::Acquire) {
            return;
        }
        for (queue_index, (registers, event)) in self
            .queue_registers
            .iter_mut()
            .zip(self.state.queue_evts())
            .enumerate()
        {
            if registers.notification_pending {
                registers.notification_pending = false;
                if let Err(err) = event.write(QUEUE_EVENT_SIGNAL) {
                    warn!("failed to notify virtio-pci queue {queue_index}: {err}");
                }
            }
        }
    }

    fn read_pci_cfg_region(&mut self, data: &mut [u8]) {
        if let Some((PCI_BAR0_INDEX, selected_offset, len)) = self.pci_cfg_selection()
            && data.len() == len
        {
            self.read_bar_region(u64::from(selected_offset), data);
        } else {
            data.fill(PCI_UNIMPLEMENTED_READ_BYTE);
        }
    }

    fn write_pci_cfg_region(&mut self, data: &[u8]) {
        if let Some((PCI_BAR0_INDEX, selected_offset, len)) = self.pci_cfg_selection()
            && data.len() == len
        {
            self.write_bar_region(u64::from(selected_offset), data);
        }
    }
}

impl PciFunction for VirtioPciTransport {
    fn read_config(&mut self, offset: u16, data: &mut [u8]) {
        let start = usize::from(offset);
        let Some(end) = start.checked_add(data.len()) else {
            data.fill(PCI_UNIMPLEMENTED_READ_BYTE);
            return;
        };
        if end > PCI_CONFIG_SIZE {
            data.fill(PCI_UNIMPLEMENTED_READ_BYTE);
            return;
        }

        if let Some(cap_offset) = self.pci_cfg_cap_offset {
            let data_start = cap_offset + vendor_cap::PCI_CONFIG_DATA;
            if start >= data_start && end <= data_start + PCI_CFG_DATA_SIZE {
                if start == data_start {
                    self.read_pci_cfg_region(data);
                } else {
                    data.fill(PCI_UNIMPLEMENTED_READ_BYTE);
                }
                return;
            }
        }

        for (index, byte) in data.iter_mut().enumerate() {
            *byte = self.config_byte(start + index);
        }
    }

    fn write_config(&mut self, offset: u16, data: &[u8]) {
        let start = usize::from(offset);
        let Some(end) = start.checked_add(data.len()) else {
            return;
        };
        if end > PCI_CONFIG_SIZE {
            return;
        }

        if let Some(pci_cfg_cap_offset) = self.pci_cfg_cap_offset {
            let data_start = pci_cfg_cap_offset + vendor_cap::PCI_CONFIG_DATA;
            if start >= data_start && end <= data_start + PCI_CFG_DATA_SIZE {
                if start == data_start {
                    self.write_pci_cfg_region(data);
                }
                return;
            }
        }

        if start == pci_config::BAR0 && data.len() == PCI_BAR0_SIZE {
            let value = u32::from_le_bytes(data.try_into().unwrap());
            if value == PCI_BAR_PROBE_VALUE {
                self.bar_probe = true;
                return;
            }
        }

        let command_end = pci_config::COMMAND + WORD_SIZE;
        let command_register_touched = start < command_end && end > pci_config::COMMAND;
        let bus_master_was_enabled = self.bus_master_enabled.load(Ordering::Acquire);
        for (index, value) in data.iter().copied().enumerate() {
            let register = start + index;
            match register {
                pci_config::COMMAND..=PCI_COMMAND_LAST_BYTE => {
                    self.config.write_u8(register, value)
                }
                pci_config::BAR0..=PCI_BAR0_END => {
                    self.bar_probe = false;
                    let mut bytes = self.bar_base.to_le_bytes();
                    let byte_offset = register - pci_config::BAR0;
                    if let Some(byte) = bytes.get_mut(byte_offset) {
                        *byte = value;
                    }
                    self.bar_base = u32::from_le_bytes(bytes) & VIRTIO_PCI_BAR0_ADDRESS_MASK;
                }
                register
                    if self
                        .msix_cap_offset
                        .is_some_and(|offset| register == offset + msix_cap::CONTROL + 1) =>
                {
                    // Only the enable and function mask bits are writable; the
                    // table size is read-only.
                    let offset = self.msix_cap_offset.unwrap();
                    let control = (self
                        .config
                        .read_u16(offset + msix_cap::CONTROL)
                        .unwrap_or(0)
                        & 0x07ff)
                        | (u16::from(value) << 8)
                            & (MSIX_CONTROL_ENABLE | MSIX_CONTROL_FUNCTION_MASK);
                    self.config.write_u16(offset + msix_cap::CONTROL, control);
                    if let Some(msix) = &self.msix {
                        let mut msix = msix.lock().unwrap();
                        msix.enabled = control & MSIX_CONTROL_ENABLE != 0;
                        msix.function_masked = control & MSIX_CONTROL_FUNCTION_MASK != 0;
                        msix.sync_all();
                    }
                }
                _ => {
                    if let Some(cap_offset) = self.pci_cfg_cap_offset {
                        let cap_field = register.checked_sub(cap_offset);
                        if cap_field.is_some_and(|field| {
                            field == vendor_cap::BAR
                                || (vendor_cap::REGION_OFFSET
                                    ..vendor_cap::REGION_OFFSET + DWORD_SIZE)
                                    .contains(&field)
                                || (vendor_cap::REGION_LENGTH
                                    ..vendor_cap::REGION_LENGTH + DWORD_SIZE)
                                    .contains(&field)
                        }) {
                            self.config.write_u8(register, value);
                        }
                    }
                }
            }
        }

        if command_register_touched {
            let command = self
                .config
                .read_u16(pci_config::COMMAND)
                .expect("PCI command register fits in configuration space");
            let bus_master_enabled = command & PCI_COMMAND_MASTER != 0;
            self.bus_master_enabled
                .store(bus_master_enabled, Ordering::Release);
            self.interrupt
                .set_intx_disabled(command & PCI_COMMAND_INTX_DISABLE != 0);
            if !bus_master_was_enabled && bus_master_enabled {
                self.activate_if_ready();
            }
        }
        self.update_queue_notifications();
    }

    fn read_bar(&mut self, address: u64, data: &mut [u8]) -> PciBarAccess {
        let command = self
            .config
            .read_u16(pci_config::COMMAND)
            .expect("PCI command register fits in configuration space");
        if command & PCI_COMMAND_MEMORY == 0 || self.bar_base == 0 {
            return PciBarAccess::Unhandled;
        }
        let base = u64::from(self.bar_base);
        let Some(offset) = address.checked_sub(base) else {
            return PciBarAccess::Unhandled;
        };
        if offset
            .checked_add(data.len() as u64)
            .is_none_or(|end| end > VIRTIO_PCI_BAR0_SIZE)
        {
            return PciBarAccess::Unhandled;
        }
        self.read_bar_region(offset, data)
    }

    fn write_bar(&mut self, address: u64, data: &[u8]) -> PciBarAccess {
        let command = self
            .config
            .read_u16(pci_config::COMMAND)
            .expect("PCI command register fits in configuration space");
        if command & PCI_COMMAND_MEMORY == 0 || self.bar_base == 0 {
            return PciBarAccess::Unhandled;
        }
        let base = u64::from(self.bar_base);
        let Some(offset) = address.checked_sub(base) else {
            return PciBarAccess::Unhandled;
        };
        if offset
            .checked_add(data.len() as u64)
            .is_none_or(|end| end > VIRTIO_PCI_BAR0_SIZE)
        {
            return PciBarAccess::Unhandled;
        }
        self.write_bar_region(offset, data)
    }
}

const PCI_SNAPSHOT_VERSION: u8 = 1;

#[derive(bincode::Encode, bincode::Decode)]
struct SavedPci {
    transport: SavedTransport,
    config: Vec<u8>,
    bar_base: u32,
    bar_probe: bool,
    /// Each queue's `(size, enabled, notification_pending)`.
    queues: Vec<(u16, bool, bool)>,
    isr: u8,
    intx_disabled: bool,
    msix: Option<SavedMsix>,
}

#[derive(bincode::Encode, bincode::Decode)]
struct SavedMsix {
    enabled: bool,
    function_masked: bool,
    /// Each vector's `(address, data, masked)`.
    table: Vec<(u64, u32, bool)>,
    pending: Vec<bool>,
    config_vector: u16,
    queue_vectors: Vec<u16>,
}

impl Snapshottable for VirtioPciTransport {
    fn pause(&mut self) -> Result<(), crate::Error> {
        self.state.pause()
    }

    fn save(&self) -> Result<SavedState, crate::Error> {
        let (isr, intx_disabled) = self.interrupt.saved();
        let msix = self.msix.as_ref().map(|msix| {
            let msix = msix.lock().unwrap();
            SavedMsix {
                enabled: msix.enabled,
                function_masked: msix.function_masked,
                table: msix
                    .table
                    .iter()
                    .map(|e| (e.address, e.data, e.masked))
                    .collect(),
                pending: msix.pending.clone(),
                config_vector: msix.config_vector,
                queue_vectors: msix.queue_vectors.clone(),
            }
        });
        let saved = SavedPci {
            transport: self.state.save()?,
            config: self.config.0.to_vec(),
            bar_base: self.bar_base,
            bar_probe: self.bar_probe,
            queues: self
                .queue_registers
                .iter()
                .map(|q| (q.size, q.enabled, q.notification_pending))
                .collect(),
            isr,
            intx_disabled,
            msix,
        };
        let bytes = bincode::encode_to_vec(&saved, bincode::config::standard())
            .map_err(|e| crate::Error::Snapshot(e.to_string()))?;
        Ok(SavedState {
            version: PCI_SNAPSHOT_VERSION,
            bytes,
        })
    }

    fn restore(&mut self, state: &SavedState) -> Result<(), crate::Error> {
        let err = |e: &str| crate::Error::Snapshot(format!("virtio-pci: {e}"));
        if state.version != PCI_SNAPSHOT_VERSION {
            return Err(err(&format!("unsupported state version {}", state.version)));
        }
        let (saved, _): (SavedPci, _) =
            bincode::decode_from_slice(&state.bytes, bincode::config::standard())
                .map_err(|e| err(&e.to_string()))?;
        if saved.config.len() != PCI_CONFIG_SIZE {
            return Err(err("configuration space size"));
        }
        if saved.queues.len() != self.queue_registers.len() {
            return Err(err("queue count"));
        }
        if saved.msix.is_some() != self.msix.is_some() {
            return Err(err("MSI-X offered in one and not the other"));
        }

        self.state.restore(&saved.transport)?;
        self.config.0.copy_from_slice(&saved.config);
        self.bar_base = saved.bar_base;
        self.bar_probe = saved.bar_probe;
        for (registers, &(size, enabled, notification_pending)) in
            self.queue_registers.iter_mut().zip(&saved.queues)
        {
            registers.size = size;
            registers.enabled = enabled;
            registers.notification_pending = notification_pending;
        }
        let command = self
            .config
            .read_u16(pci_config::COMMAND)
            .expect("PCI command register fits in configuration space");
        self.bus_master_enabled
            .store(command & PCI_COMMAND_MASTER != 0, Ordering::Release);

        if let (Some(msix), Some(saved_msix)) = (&self.msix, &saved.msix) {
            let mut msix = msix.lock().unwrap();
            if saved_msix.table.len() != msix.table.len()
                || saved_msix.queue_vectors.len() != msix.queue_vectors.len()
            {
                return Err(err("MSI-X vector count"));
            }
            msix.enabled = saved_msix.enabled;
            msix.function_masked = saved_msix.function_masked;
            for (entry, &(address, data, masked)) in msix.table.iter_mut().zip(&saved_msix.table) {
                *entry = MsixEntry {
                    address,
                    data,
                    masked,
                };
            }
            msix.pending.copy_from_slice(&saved_msix.pending);
            msix.config_vector = saved_msix.config_vector;
            msix.queue_vectors
                .copy_from_slice(&saved_msix.queue_vectors);
            // Routes the vectors the guest had unmasked, and delivers the
            // ones left pending.
            msix.sync_all();
        }
        self.interrupt.restore(saved.isr, saved.intx_disabled);
        self.update_queue_notifications();
        Ok(())
    }

    fn resume(&mut self) -> Result<(), crate::Error> {
        self.state.resume(self.device_interrupt.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BusDevice;
    use crate::virtio::{ActivateResult, DeviceQueue, QueueConfig};
    use std::sync::atomic::{AtomicBool, Ordering};
    use vm_memory::GuestAddress;

    const TEST_DEVICE_TYPE: u32 = 1;
    const TEST_QUEUE_SIZE: u16 = 8;
    const TEST_SELECTED_QUEUE_SIZE: u16 = 4;
    const TEST_BAR_BASE: u32 = 0xe100_0000;
    const TEST_RELOCATED_BAR_BASE: u32 = TEST_BAR_BASE + VIRTIO_PCI_BAR0_SIZE as u32;
    const TEST_GUEST_MEMORY_SIZE: usize = 0x10000;
    const TEST_DESCRIPTOR_ADDRESS: u32 = 0x1000;
    const TEST_DRIVER_ADDRESS: u32 = 0x2000;
    const TEST_DEVICE_ADDRESS: u32 = 0x3000;

    static QUEUE_CONFIG: [QueueConfig; 1] = [QueueConfig::new(TEST_QUEUE_SIZE)];
    static MULTI_QUEUE_CONFIG: [QueueConfig; 2] = [
        QueueConfig::new(TEST_QUEUE_SIZE),
        QueueConfig::new(TEST_QUEUE_SIZE),
    ];
    const DEVICE_CONFIG: [u8; DWORD_SIZE] = [0x12, 0x34, 0x56, 0x78];
    const TEST_PCI_ADDRESS: crate::pci::PciAddress = crate::pci::PciAddress {
        bus: 0,
        device: 1,
        function: 0,
    };

    #[derive(Default)]
    struct DummyIntxLine(AtomicBool);

    impl PciIntxLine for DummyIntxLine {
        fn set_level(&self, asserted: bool) -> io::Result<()> {
            self.0.store(asserted, Ordering::SeqCst);
            Ok(())
        }
    }

    struct DummyDevice {
        acked_features: u64,
        activated: bool,
        queue_config: &'static [QueueConfig],
    }

    impl VirtioDevice for DummyDevice {
        fn avail_features(&self) -> u64 {
            1u64 << VIRTIO_F_VERSION_1
        }

        fn acked_features(&self) -> u64 {
            self.acked_features
        }

        fn set_acked_features(&mut self, features: u64) {
            self.acked_features = features;
        }

        fn device_type(&self) -> u32 {
            TEST_DEVICE_TYPE
        }

        fn device_name(&self) -> &str {
            "pci-test"
        }

        fn queue_config(&self) -> &[QueueConfig] {
            self.queue_config
        }

        fn config_len(&self) -> Option<u32> {
            Some(DEVICE_CONFIG.len() as u32)
        }

        fn read_config(&self, offset: u64, data: &mut [u8]) {
            let start = offset as usize;
            let end = start + data.len();
            let config = DEVICE_CONFIG
                .get(start..end)
                .expect("test device configuration read is in bounds");
            data.copy_from_slice(config);
        }

        fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

        fn activate(
            &mut self,
            _mem: GuestMemoryMmap,
            _interrupt: InterruptTransport,
            _queues: Vec<DeviceQueue>,
        ) -> ActivateResult {
            self.activated = true;
            Ok(())
        }

        fn is_activated(&self) -> bool {
            self.activated
        }

        fn reset(&mut self) -> bool {
            self.activated = false;
            true
        }
    }

    fn transport_with_queue_config(
        queue_config: &'static [QueueConfig],
    ) -> (VirtioPciTransport, Arc<DummyIntxLine>) {
        let mem =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), TEST_GUEST_MEMORY_SIZE)]).unwrap();
        let intx_line = Arc::new(DummyIntxLine::default());
        let transport = VirtioPciTransport::new(
            mem,
            Arc::new(Mutex::new(DummyDevice {
                acked_features: 0,
                activated: false,
                queue_config,
            })),
            5,
            intx_line.clone(),
            0,
            None,
        )
        .unwrap();
        (transport, intx_line)
    }

    #[derive(Default)]
    struct RecordingVectors {
        routes: Mutex<Vec<(u16, Option<(u64, u32)>)>>,
        signals: Mutex<Vec<u16>>,
    }

    impl PciMsiVectors for RecordingVectors {
        fn count(&self) -> u16 {
            2
        }

        fn route(&self, vector: u16, message: Option<(u64, u32)>) -> io::Result<()> {
            self.routes.lock().unwrap().push((vector, message));
            Ok(())
        }

        fn signal(&self, vector: u16) -> io::Result<()> {
            self.signals.lock().unwrap().push(vector);
            Ok(())
        }
    }

    #[test]
    fn msix_routes_unmasked_vectors_and_holds_masked_ones_pending() {
        let mem =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), TEST_GUEST_MEMORY_SIZE)]).unwrap();
        let intx_line = Arc::new(DummyIntxLine::default());
        let vectors = Arc::new(RecordingVectors::default());
        let mut transport = VirtioPciTransport::new(
            mem,
            Arc::new(Mutex::new(DummyDevice {
                acked_features: 0,
                activated: false,
                queue_config: &QUEUE_CONFIG,
            })),
            5,
            intx_line.clone(),
            0,
            Some(vectors.clone()),
        )
        .unwrap();
        let base = enable_memory_bar(&mut transport);
        let cap = transport.msix_cap_offset.unwrap();

        // Two vectors: the table size field holds N - 1.
        let mut control = [0; 2];
        read_config(
            &mut transport,
            (cap + msix_cap::CONTROL) as u16,
            &mut control,
        );
        assert_eq!(u16::from_le_bytes(control), 1);

        // Assign vector 1 to queue 0 and program its entry while masked, as
        // Linux does, then enable MSI-X.
        write_bar(
            &mut transport,
            base,
            common_cfg::QUEUE_SELECT,
            &0u16.to_le_bytes(),
        );
        write_bar(
            &mut transport,
            base,
            common_cfg::QUEUE_MSIX_VECTOR,
            &1u16.to_le_bytes(),
        );
        let mut vector = [0; 2];
        read_bar(
            &mut transport,
            base + common_cfg::QUEUE_MSIX_VECTOR,
            &mut vector,
        );
        assert_eq!(u16::from_le_bytes(vector), 1);
        let entry = MSIX_TABLE_OFFSET + MSIX_ENTRY_SIZE;
        write_bar(&mut transport, base, entry, &0x0801_0040u32.to_le_bytes());
        write_bar(&mut transport, base, entry + 4, &0u32.to_le_bytes());
        write_bar(&mut transport, base, entry + 8, &7u32.to_le_bytes());
        write_config(
            &mut transport,
            (cap + msix_cap::CONTROL) as u16,
            &MSIX_CONTROL_ENABLE.to_le_bytes(),
        );

        // While the entry is masked, the interrupt is only marked pending.
        transport
            .device_interrupt
            .for_queue(0)
            .try_signal_used_queue()
            .unwrap();
        assert!(vectors.signals.lock().unwrap().is_empty());
        let mut pba = [0; 1];
        read_bar(&mut transport, base + MSIX_PBA_OFFSET, &mut pba);
        assert_eq!(pba[0], 0b10);

        // Unmasking routes the vector and signals the pending interrupt.
        write_bar(&mut transport, base, entry + 12, &0u32.to_le_bytes());
        assert_eq!(
            vectors.routes.lock().unwrap().last(),
            Some(&(1, Some((0x0801_0040, 7))))
        );
        assert_eq!(*vectors.signals.lock().unwrap(), vec![1]);

        // Later interrupts are signalled directly.
        transport
            .device_interrupt
            .for_queue(0)
            .try_signal_used_queue()
            .unwrap();
        assert_eq!(*vectors.signals.lock().unwrap(), vec![1, 1]);
        assert!(!intx_line.0.load(Ordering::SeqCst));
    }

    fn transport_with_line() -> (VirtioPciTransport, Arc<DummyIntxLine>) {
        transport_with_queue_config(&QUEUE_CONFIG)
    }

    fn transport() -> VirtioPciTransport {
        transport_with_line().0
    }

    fn read_config(transport: &mut VirtioPciTransport, offset: u16, data: &mut [u8]) {
        PciFunction::read_config(transport, offset, data);
    }

    fn write_config(transport: &mut VirtioPciTransport, offset: u16, data: &[u8]) {
        PciFunction::write_config(transport, offset, data);
    }

    fn enable_memory_bar(transport: &mut VirtioPciTransport) -> u64 {
        let bar = TEST_BAR_BASE;
        write_config(
            transport,
            pci_config::COMMAND as u16,
            &(PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER).to_le_bytes(),
        );
        write_config(transport, pci_config::BAR0 as u16, &bar.to_le_bytes());
        u64::from(bar)
    }

    fn write_bar(transport: &mut VirtioPciTransport, base: u64, offset: u64, data: &[u8]) {
        assert_eq!(
            PciFunction::write_bar(transport, base + offset, data),
            PciBarAccess::Handled
        );
    }

    fn read_bar(transport: &mut VirtioPciTransport, address: u64, data: &mut [u8]) {
        assert_eq!(
            PciFunction::read_bar(transport, address, data),
            PciBarAccess::Handled
        );
    }

    #[test]
    fn advertises_modern_virtio_identity_and_capabilities() {
        let mut transport = transport();
        let mut vendor_id = [0; WORD_SIZE];
        read_config(&mut transport, pci_config::VENDOR_ID as u16, &mut vendor_id);
        assert_eq!(u16::from_le_bytes(vendor_id), PCI_VENDOR_ID_VIRTIO);
        let mut device_id = [0; WORD_SIZE];
        read_config(&mut transport, pci_config::DEVICE_ID as u16, &mut device_id);
        assert_eq!(
            u16::from_le_bytes(device_id),
            PCI_DEVICE_ID_VIRTIO_MODERN.wrapping_add(TEST_DEVICE_TYPE as u16)
        );

        let mut pointer = transport
            .config
            .read_u8(pci_config::CAPABILITY_POINTER)
            .unwrap();
        let mut cfg_types = Vec::new();
        while pointer != 0 {
            let offset = usize::from(pointer);
            cfg_types.push(
                transport
                    .config
                    .read_u8(offset + vendor_cap::CONFIG_TYPE)
                    .unwrap(),
            );
            pointer = transport.config.read_u8(offset + vendor_cap::NEXT).unwrap();
        }
        assert_eq!(
            cfg_types,
            [
                VIRTIO_PCI_CAP_COMMON_CFG,
                VIRTIO_PCI_CAP_NOTIFY_CFG,
                VIRTIO_PCI_CAP_ISR_CFG,
                VIRTIO_PCI_CAP_DEVICE_CFG,
                VIRTIO_PCI_CAP_PCI_CFG,
            ]
        );
    }

    #[test]
    fn bar_probe_and_device_configuration_are_routed() {
        let mut transport = transport();
        write_config(
            &mut transport,
            pci_config::BAR0 as u16,
            &PCI_BAR_PROBE_VALUE.to_le_bytes(),
        );
        let mut bar = [0; DWORD_SIZE];
        read_config(&mut transport, pci_config::BAR0 as u16, &mut bar);
        let expected_probe = (!(VIRTIO_PCI_BAR0_SIZE as u32 - 1)) & PCI_BAR_ADDRESS_MASK;
        assert_eq!(u32::from_le_bytes(bar), expected_probe);

        let bar_base = enable_memory_bar(&mut transport);
        let mut config = [0; 4];
        read_bar(&mut transport, bar_base + DEVICE_CFG_OFFSET, &mut config);
        assert_eq!(config, DEVICE_CONFIG);
    }

    #[test]
    fn bar_router_follows_config_space_relocation() {
        let function: Arc<Mutex<dyn PciFunction>> = Arc::new(Mutex::new(transport()));
        let root = crate::pci::PciRoot::shared();
        root.lock()
            .unwrap()
            .insert(TEST_PCI_ADDRESS, function)
            .unwrap();
        let mut config = crate::pci::ConfigMechanism1::new(root.clone());
        let mut bars = crate::pci::BarWindow::new(root, u64::from(TEST_BAR_BASE));
        let first_bar = TEST_BAR_BASE;
        let second_bar = TEST_RELOCATED_BAR_BASE;
        let selector = TEST_PCI_ADDRESS.config_mechanism_1_selector(pci_config::BAR0 as u16);
        config.write(
            0,
            crate::pci::CONFIG_MECHANISM_1_ADDRESS_PORT_OFFSET,
            &selector.to_le_bytes(),
        );
        config.write(
            0,
            crate::pci::CONFIG_MECHANISM_1_DATA_PORT_OFFSET,
            &first_bar.to_le_bytes(),
        );

        let mut value = [0; 4];
        bars.read(0, u64::from(DEVICE_CFG_OFFSET), &mut value);
        assert_eq!(value, DEVICE_CONFIG);

        config.write(
            0,
            crate::pci::CONFIG_MECHANISM_1_DATA_PORT_OFFSET,
            &second_bar.to_le_bytes(),
        );
        bars.read(0, u64::from(DEVICE_CFG_OFFSET), &mut value);
        assert_eq!(value, [PCI_UNIMPLEMENTED_READ_BYTE; DWORD_SIZE]);
        bars.read(
            0,
            u64::from(second_bar - first_bar) + u64::from(DEVICE_CFG_OFFSET),
            &mut value,
        );
        assert_eq!(value, DEVICE_CONFIG);
    }

    #[test]
    fn pci_cfg_capability_proxies_bar_accesses() {
        let mut transport = transport();
        let pci_cfg = transport
            .capabilities
            .iter()
            .find(|capability| capability.cfg_type == VIRTIO_PCI_CAP_PCI_CFG)
            .unwrap()
            .offset;
        write_config(
            &mut transport,
            u16::from(pci_cfg) + vendor_cap::REGION_OFFSET as u16,
            &(DEVICE_CFG_OFFSET as u32).to_le_bytes(),
        );
        write_config(
            &mut transport,
            u16::from(pci_cfg) + vendor_cap::REGION_LENGTH as u16,
            &(PCI_CFG_DATA_SIZE as u32).to_le_bytes(),
        );

        let mut config = [0; PCI_CFG_DATA_SIZE];
        read_config(
            &mut transport,
            u16::from(pci_cfg) + vendor_cap::PCI_CONFIG_DATA as u16,
            &mut config,
        );
        assert_eq!(config, DEVICE_CONFIG);
    }

    #[test]
    fn queue_notifications_and_isr_follow_pci_bar_accesses() {
        let (mut transport, intx_line) = transport_with_line();
        let bar_base = enable_memory_bar(&mut transport);
        let queue_event = transport.state.queue_evts().first().unwrap().clone();

        assert_eq!(
            PciFunction::write_bar(&mut transport, bar_base + NOTIFY_CFG_OFFSET, &[0, 0]),
            PciBarAccess::Handled
        );
        assert_eq!(queue_event.read().unwrap(), QUEUE_EVENT_SIGNAL);

        transport.device_interrupt.try_signal_used_queue().unwrap();
        transport
            .device_interrupt
            .try_signal_config_change()
            .unwrap();
        assert!(intx_line.0.load(Ordering::SeqCst));
        let mut pci_status = [0; WORD_SIZE];
        read_config(&mut transport, pci_config::STATUS as u16, &mut pci_status);
        assert_ne!(u16::from_le_bytes(pci_status) & PCI_STATUS_INTERRUPT, 0);

        let mut isr = [0; BYTE_SIZE];
        read_bar(&mut transport, bar_base + ISR_CFG_OFFSET, &mut isr);
        assert_eq!(isr, [VIRTIO_ISR_QUEUE | VIRTIO_ISR_CONFIG]);
        assert!(!intx_line.0.load(Ordering::SeqCst));

        pci_status = [0; 2];
        read_config(&mut transport, pci_config::STATUS as u16, &mut pci_status);
        assert_eq!(u16::from_le_bytes(pci_status) & PCI_STATUS_INTERRUPT, 0);
    }

    #[test]
    fn intx_disable_masks_and_replays_pending_interrupts() {
        let (mut transport, intx_line) = transport_with_line();
        let command = PCI_COMMAND_MEMORY | PCI_COMMAND_INTX_DISABLE;
        write_config(&mut transport, 4, &command.to_le_bytes());
        transport.device_interrupt.try_signal_used_queue().unwrap();
        assert!(!intx_line.0.load(Ordering::SeqCst));

        write_config(&mut transport, 4, &PCI_COMMAND_MEMORY.to_le_bytes());
        assert!(intx_line.0.load(Ordering::SeqCst));

        let bar_base = u64::from(TEST_BAR_BASE);
        write_config(
            &mut transport,
            pci_config::BAR0 as u16,
            &(bar_base as u32).to_le_bytes(),
        );
        let mut isr = [0; BYTE_SIZE];
        read_bar(&mut transport, bar_base + ISR_CFG_OFFSET, &mut isr);
        assert_eq!(isr, [VIRTIO_ISR_QUEUE]);
        assert!(!intx_line.0.load(Ordering::SeqCst));
    }

    #[test]
    fn queue_common_configuration_uses_virtio_register_widths() {
        let mut transport = transport();
        let bar_base = enable_memory_bar(&mut transport);
        let mut value = [0; WORD_SIZE];
        read_bar(
            &mut transport,
            bar_base + common_cfg::NUMBER_OF_QUEUES,
            &mut value,
        );
        assert_eq!(u16::from_le_bytes(value), 1);

        let mut wrong_width = [0; DWORD_SIZE];
        read_bar(
            &mut transport,
            bar_base + common_cfg::NUMBER_OF_QUEUES,
            &mut wrong_width,
        );
        assert_eq!(wrong_width, [PCI_UNIMPLEMENTED_READ_BYTE; DWORD_SIZE]);
    }

    #[test]
    fn queue_setup_activation_and_device_reset_use_shared_state() {
        let mut transport = transport();
        let bar_base = enable_memory_bar(&mut transport);
        let queue_event = transport.state.queue_evts().first().unwrap().clone();
        let mut queue_size = [0; WORD_SIZE];
        read_bar(
            &mut transport,
            bar_base + common_cfg::QUEUE_SIZE,
            &mut queue_size,
        );
        assert_eq!(u16::from_le_bytes(queue_size), TEST_QUEUE_SIZE);

        write_bar(
            &mut transport,
            bar_base,
            common_cfg::DEVICE_STATUS,
            &[device_status::ACKNOWLEDGE as u8],
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::DEVICE_STATUS,
            &[(device_status::ACKNOWLEDGE | device_status::DRIVER) as u8],
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::DEVICE_STATUS,
            &[
                (device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK)
                    as u8,
            ],
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::QUEUE_SELECT,
            &0u16.to_le_bytes(),
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::QUEUE_SIZE,
            &TEST_SELECTED_QUEUE_SIZE.to_le_bytes(),
        );
        read_bar(
            &mut transport,
            bar_base + common_cfg::QUEUE_SIZE,
            &mut queue_size,
        );
        assert_eq!(u16::from_le_bytes(queue_size), TEST_SELECTED_QUEUE_SIZE);
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::QUEUE_DESCRIPTOR,
            &TEST_DESCRIPTOR_ADDRESS.to_le_bytes(),
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::QUEUE_DRIVER,
            &TEST_DRIVER_ADDRESS.to_le_bytes(),
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::QUEUE_DEVICE,
            &TEST_DEVICE_ADDRESS.to_le_bytes(),
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::QUEUE_ENABLE,
            &VIRTIO_QUEUE_READY.to_le_bytes(),
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::DEVICE_STATUS,
            &[(device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK) as u8],
        );

        assert!(transport.state.locked_device().is_activated());
        assert!(queue_event.read().is_err());
        read_bar(
            &mut transport,
            bar_base + common_cfg::QUEUE_SIZE,
            &mut queue_size,
        );
        assert_eq!(u16::from_le_bytes(queue_size), TEST_SELECTED_QUEUE_SIZE);
        let mut queue_enable = [0; WORD_SIZE];
        read_bar(
            &mut transport,
            bar_base + common_cfg::QUEUE_ENABLE,
            &mut queue_enable,
        );
        assert_eq!(u16::from_le_bytes(queue_enable), VIRTIO_QUEUE_READY);

        write_bar(
            &mut transport,
            bar_base,
            common_cfg::DEVICE_STATUS,
            &[device_status::INIT as u8],
        );
        assert_eq!(transport.state.device_status, device_status::INIT);
        assert!(!transport.state.locked_device().is_activated());
        assert!(transport.state.queues.is_some());
        read_bar(
            &mut transport,
            bar_base + common_cfg::QUEUE_SIZE,
            &mut queue_size,
        );
        assert_eq!(u16::from_le_bytes(queue_size), TEST_QUEUE_SIZE);
        read_bar(
            &mut transport,
            bar_base + common_cfg::QUEUE_ENABLE,
            &mut queue_enable,
        );
        assert_eq!(u16::from_le_bytes(queue_enable), 0);
    }

    #[derive(Default)]
    struct RecordingQueueNotifications(Mutex<Vec<(Option<u64>, Option<u64>)>>);

    impl PciQueueNotifications for RecordingQueueNotifications {
        fn relocate(&self, from: Option<u64>, to: Option<u64>) -> io::Result<()> {
            self.0.lock().unwrap().push((from, to));
            Ok(())
        }
    }

    #[test]
    fn queue_notifications_follow_bar0_while_bus_mastering_is_on() {
        let mut transport = transport();
        let notifications = Arc::new(RecordingQueueNotifications::default());
        transport.set_queue_notifications(notifications.clone());
        let bar0 = pci_config::BAR0 as u16;
        let command = pci_config::COMMAND as u16;
        let first = u64::from(TEST_BAR_BASE);
        let second = u64::from(TEST_RELOCATED_BAR_BASE);

        write_config(&mut transport, bar0, &TEST_BAR_BASE.to_le_bytes());
        write_config(
            &mut transport,
            command,
            &(PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER).to_le_bytes(),
        );
        write_config(&mut transport, bar0, &PCI_BAR_PROBE_VALUE.to_le_bytes());
        write_config(&mut transport, bar0, &TEST_BAR_BASE.to_le_bytes());
        write_config(&mut transport, bar0, &TEST_RELOCATED_BAR_BASE.to_le_bytes());
        write_config(&mut transport, command, &PCI_COMMAND_MEMORY.to_le_bytes());
        write_config(
            &mut transport,
            command,
            &(PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER).to_le_bytes(),
        );

        assert_eq!(
            *notifications.0.lock().unwrap(),
            [
                (None, Some(first)),
                (Some(first), Some(second)),
                (Some(second), None),
                (None, Some(second)),
            ]
        );
    }

    #[test]
    fn bus_master_enable_gates_pci_queue_activation_and_notifications() {
        let (mut transport, _) = transport_with_queue_config(&MULTI_QUEUE_CONFIG);
        let bar_base = u64::from(TEST_BAR_BASE);
        write_config(
            &mut transport,
            pci_config::COMMAND as u16,
            &PCI_COMMAND_MEMORY.to_le_bytes(),
        );
        write_config(
            &mut transport,
            pci_config::BAR0 as u16,
            &(bar_base as u32).to_le_bytes(),
        );
        let queue_events = transport.state.queue_evts().to_vec();

        write_bar(
            &mut transport,
            bar_base,
            common_cfg::DEVICE_STATUS,
            &[device_status::ACKNOWLEDGE as u8],
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::DEVICE_STATUS,
            &[(device_status::ACKNOWLEDGE | device_status::DRIVER) as u8],
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::DEVICE_STATUS,
            &[
                (device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK)
                    as u8,
            ],
        );
        write_bar(
            &mut transport,
            bar_base,
            common_cfg::DEVICE_STATUS,
            &[(device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK) as u8],
        );
        assert!(!transport.state.locked_device().is_activated());

        write_bar(
            &mut transport,
            bar_base,
            NOTIFY_CFG_OFFSET + u64::from(NOTIFY_OFF_MULTIPLIER),
            &0u16.to_le_bytes(),
        );
        assert!(queue_events[0].read().is_err());
        assert!(queue_events[1].read().is_err());

        write_config(
            &mut transport,
            pci_config::COMMAND as u16,
            &(PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER).to_le_bytes(),
        );
        assert!(transport.state.locked_device().is_activated());
        assert!(queue_events[0].read().is_err());
        assert_eq!(queue_events[1].read().unwrap(), QUEUE_EVENT_SIGNAL);

        write_config(
            &mut transport,
            pci_config::COMMAND as u16,
            &PCI_COMMAND_MEMORY.to_le_bytes(),
        );

        write_bar(
            &mut transport,
            bar_base,
            NOTIFY_CFG_OFFSET,
            &0u16.to_le_bytes(),
        );
        assert!(queue_events[0].read().is_err());
        assert!(queue_events[1].read().is_err());

        write_config(
            &mut transport,
            pci_config::COMMAND as u16,
            &(PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER).to_le_bytes(),
        );
        assert_eq!(queue_events[0].read().unwrap(), QUEUE_EVENT_SIGNAL);
        assert!(queue_events[1].read().is_err());
    }
}
