// Copyright 2026 The libkrun Authors.
// SPDX-License-Identifier: Apache-2.0

//! PCI root and virtio-pci registration for the KVM backend: on x86_64,
//! described to the guest by ACPI; on aarch64, by the device tree, a generic
//! ECAM host bridge.

use std::fmt::{Display, Formatter};
use std::io;
use std::sync::{Arc, Mutex};

use devices::Bus;
#[cfg(target_arch = "x86_64")]
use devices::pci::ConfigMechanism1;
use devices::pci::{
    BarWindow, Ecam, PciAddress, PciFunction, PciIntxLine, PciQueueNotifications, PciRootError,
};
use devices::virtio::{
    CreatePciTransportError, VIRTIO_PCI_BAR0_SIZE, VirtioDevice, VirtioPciTransport,
};
use kvm_ioctls::{IoEventAddress, NoDatamatch, VmFd};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

use crate::vmm::device_manager::irq::IrqAllocator;

const PCI_BUS0: u8 = 0;

#[derive(Debug)]
pub enum Error {
    Bus(devices::BusError),
    CreateTransport(CreatePciTransportError),
    IrqsExhausted,
    PciRoot(PciRootError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bus(err) => write!(f, "failed to register PCI bus device: {err}"),
            Self::CreateTransport(err) => write!(f, "failed to create virtio-pci transport: {err}"),
            Self::IrqsExhausted => write!(f, "no more GSIs are available for PCI INTx"),
            Self::PciRoot(err) => write!(f, "failed to register PCI function: {err}"),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

/// A function as the guest is told of it: by ACPI on x86_64, by the device
/// tree on aarch64.
#[cfg(target_arch = "x86_64")]
pub use arch::x86_64::PciFunctionInfo;
#[cfg(target_arch = "aarch64")]
pub use devices::fdt::PciFdtFunction as PciFunctionInfo;

#[cfg(target_arch = "aarch64")]
use arch::aarch64::layout::{PCI_BAR_END, PCI_BAR_START, PCI_ECAM_SIZE, PCI_ECAM_START};
#[cfg(target_arch = "x86_64")]
use arch::x86_64::layout::{PCI_BAR_END, PCI_BAR_START, PCI_ECAM_SIZE, PCI_ECAM_START};
#[cfg(target_arch = "aarch64")]
use devices::fdt::PciFdtInfo;

/// Owns the bus-0 PCI functions and their guest address windows.
pub struct PciHostManager {
    root: devices::pci::SharedPciRoot,
    next_device: u8,
    irqs: IrqAllocator,
    functions: Vec<PciFunctionInfo>,
}

struct KvmPciIntxLine {
    vm: Arc<VmFd>,
    gsi: u32,
}

impl PciIntxLine for KvmPciIntxLine {
    fn set_level(&self, asserted: bool) -> std::io::Result<()> {
        // On aarch64 the line is named by its type and GIC interrupt ID: an
        // SPI, numbered from 32.
        #[cfg(target_arch = "aarch64")]
        let line = (kvm_bindings::KVM_ARM_IRQ_TYPE_SPI << kvm_bindings::KVM_ARM_IRQ_TYPE_SHIFT)
            | (self.gsi + 32);
        #[cfg(target_arch = "x86_64")]
        let line = self.gsi;
        self.vm
            .set_irq_line(line, asserted)
            .map_err(|err| std::io::Error::from_raw_os_error(err.errno()))
    }
}

/// Registers a function's queue notify addresses as KVM ioeventfds.
struct KvmQueueNotifications {
    vm: Arc<VmFd>,
    events: Vec<(u64, Arc<EventFd>)>,
}

impl PciQueueNotifications for KvmQueueNotifications {
    fn relocate(&self, from: Option<u64>, to: Option<u64>) -> io::Result<()> {
        let errno = |err: kvm_ioctls::Error| io::Error::from_raw_os_error(err.errno());
        if let Some(base) = from {
            for (offset, event) in &self.events {
                self.vm
                    .unregister_ioevent(event, &IoEventAddress::Mmio(base + offset), NoDatamatch)
                    .map_err(errno)?;
            }
        }
        if let Some(base) = to {
            for (offset, event) in &self.events {
                self.vm
                    .register_ioevent(event, &IoEventAddress::Mmio(base + offset), NoDatamatch)
                    .map_err(errno)?;
            }
        }
        Ok(())
    }
}

impl PciHostManager {
    pub fn new(irqs: IrqAllocator) -> Self {
        Self {
            root: devices::pci::PciRoot::shared(),
            next_device: 1,
            irqs,
            functions: Vec::new(),
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn register_config_io(&self, bus: &mut Bus) -> Result<()> {
        bus.insert(
            Arc::new(Mutex::new(ConfigMechanism1::new(self.root.clone()))),
            devices::pci::CONFIG_MECHANISM_1_ADDRESS,
            devices::pci::CONFIG_MECHANISM_1_SIZE,
        )
        .map_err(Error::Bus)
    }

    pub fn register_mmio(&self, bus: &mut Bus) -> Result<()> {
        bus.insert(
            Arc::new(Mutex::new(Ecam::new(self.root.clone()))),
            PCI_ECAM_START,
            PCI_ECAM_SIZE,
        )
        .map_err(Error::Bus)?;
        bus.insert(
            Arc::new(Mutex::new(BarWindow::new(self.root.clone(), PCI_BAR_START))),
            PCI_BAR_START,
            PCI_BAR_END - PCI_BAR_START,
        )
        .map_err(Error::Bus)
    }

    pub fn register_virtio_device(
        &mut self,
        vm: Arc<VmFd>,
        guest_memory: GuestMemoryMmap,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) -> Result<PciFunctionInfo> {
        if self.next_device > 31 {
            return Err(Error::IrqsExhausted);
        }

        let address = PciAddress::new(PCI_BUS0, self.next_device, 0);
        let bar_base = PCI_BAR_START + u64::from(self.next_device - 1) * VIRTIO_PCI_BAR0_SIZE;
        if bar_base + VIRTIO_PCI_BAR0_SIZE > PCI_BAR_END {
            return Err(Error::IrqsExhausted);
        }
        let irq = self.irqs.alloc().map_err(|_| Error::IrqsExhausted)?;
        let intx_line = Arc::new(KvmPciIntxLine {
            vm: vm.clone(),
            gsi: irq,
        });
        let mut transport =
            VirtioPciTransport::new(guest_memory, device, irq as u8, intx_line, bar_base as u32)
                .map_err(Error::CreateTransport)?;
        let events = transport.queue_notify_events();
        transport.set_queue_notifications(Arc::new(KvmQueueNotifications { vm, events }));

        let function: Arc<Mutex<dyn PciFunction>> = Arc::new(Mutex::new(transport));
        self.root
            .lock()
            .expect("Poisoned PCI root lock")
            .insert(address, function)
            .map_err(Error::PciRoot)?;

        #[cfg(target_arch = "x86_64")]
        let info = PciFunctionInfo {
            device: address.device,
            function: address.function,
            gsi: irq,
        };
        #[cfg(target_arch = "aarch64")]
        let info = PciFunctionInfo {
            device: address.device,
            irq,
        };
        self.functions.push(info);
        self.next_device += 1;
        Ok(info)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn fdt_info(&self) -> PciFdtInfo {
        PciFdtInfo {
            ecam_base: PCI_ECAM_START,
            ecam_size: PCI_ECAM_SIZE,
            bar_base: PCI_BAR_START,
            bar_size: PCI_BAR_END - PCI_BAR_START,
            functions: self.functions.clone(),
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn acpi_info(&self) -> arch::x86_64::PciHostInfo {
        arch::x86_64::PciHostInfo {
            ecam_base: arch::x86_64::layout::PCI_ECAM_START,
            bar_start: arch::x86_64::layout::PCI_BAR_START,
            bar_size: arch::x86_64::layout::PCI_BAR_END - arch::x86_64::layout::PCI_BAR_START,
            functions: self.functions.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::super::builder;
    use super::*;
    #[cfg(target_arch = "x86_64")]
    use crate::vmm::device_manager::mmio::MMIODeviceManager;
    #[cfg(target_arch = "x86_64")]
    use devices::legacy::{DummyIrqChip, KvmIoapic};
    #[cfg(target_arch = "x86_64")]
    use devices::virtio::MmioTransport;
    use devices::virtio::{ActivateResult, DeviceQueue, InterruptTransport, QueueConfig};
    use vm_memory::GuestAddress;

    /// VIRTIO_F_VERSION_1 feature bit, required by the PCI transport.
    const VIRTIO_F_VERSION_1: u32 = 32;
    const QUEUE_CONFIG: &[QueueConfig] = &[QueueConfig::new(64)];

    struct DummyDevice;

    impl VirtioDevice for DummyDevice {
        fn avail_features(&self) -> u64 {
            1u64 << VIRTIO_F_VERSION_1
        }

        fn acked_features(&self) -> u64 {
            0
        }

        fn set_acked_features(&mut self, _: u64) {}

        fn device_type(&self) -> u32 {
            0
        }

        fn device_name(&self) -> &str {
            "dummy"
        }

        fn queue_config(&self) -> &[QueueConfig] {
            QUEUE_CONFIG
        }

        fn config_len(&self) -> Option<u32> {
            Some(0)
        }

        fn read_config(&self, _offset: u64, _data: &mut [u8]) {}

        fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

        fn activate(
            &mut self,
            _mem: GuestMemoryMmap,
            _intc: InterruptTransport,
            _queues: Vec<DeviceQueue>,
        ) -> ActivateResult {
            Ok(())
        }

        fn is_activated(&self) -> bool {
            false
        }
    }

    fn dummy_device() -> Arc<Mutex<dyn VirtioDevice>> {
        Arc::new(Mutex::new(DummyDevice))
    }

    // The MMIO device's irqfd needs an in-kernel irqchip: the IOAPIC.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_mmio_and_pci_devices_get_distinct_irqs() {
        let guest_mem = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0x0), 0x1000),
            (GuestAddress(0x1000), 0x1000),
        ])
        .unwrap();
        let mut arch_mem_info = arch::ArchMemoryInfo::default();
        let vm = builder::setup_vm(&guest_mem, &mut arch_mem_info, false).unwrap();
        let _kvmioapic = KvmIoapic::new(vm.fd()).unwrap();

        let irqs = IrqAllocator::new(arch::IRQ_BASE, arch::IRQ_MAX);
        let mut mmio = MMIODeviceManager::new(&mut 0xd000_0000, irqs.clone());
        let mut pci = PciHostManager::new(irqs);

        // Same order as build_microvm(): an MMIO device (the RTC) is attached
        // before the PCI devices.
        let transport = MmioTransport::new(
            guest_mem.clone(),
            DummyIrqChip::new().into(),
            dummy_device(),
        )
        .unwrap();
        let (_, mmio_irq) = mmio
            .register_mmio_device(vm.fd(), transport, 0, "rtc".to_string())
            .unwrap();
        let first = pci
            .register_virtio_device(vm.fd_shared(), guest_mem.clone(), dummy_device())
            .unwrap();
        let second = pci
            .register_virtio_device(vm.fd_shared(), guest_mem, dummy_device())
            .unwrap();

        assert_eq!(mmio_irq, arch::IRQ_BASE);
        assert_eq!(first.gsi, arch::IRQ_BASE + 1);
        assert_eq!(second.gsi, arch::IRQ_BASE + 2);
    }

    #[test]
    fn test_pci_reports_exhausted_shared_irqs() {
        let guest_mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0x0), 0x1000)]).unwrap();
        let mut arch_mem_info = arch::ArchMemoryInfo::default();
        let vm = builder::setup_vm(&guest_mem, &mut arch_mem_info, false).unwrap();

        let irqs = IrqAllocator::new(arch::IRQ_BASE, arch::IRQ_BASE);
        // Another manager already took the only IRQ.
        irqs.alloc().unwrap();
        let mut pci = PciHostManager::new(irqs);

        let err = pci
            .register_virtio_device(vm.fd_shared(), guest_mem, dummy_device())
            .unwrap_err();
        assert!(matches!(err, Error::IrqsExhausted));
    }
}
