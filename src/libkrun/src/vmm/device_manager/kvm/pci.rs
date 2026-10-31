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
    BarWindow, Ecam, PciAddress, PciFunction, PciIntxLine, PciMsiVectors, PciQueueNotifications,
    PciRootError,
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
    EventFd(io::Error),
    RegisterIrqFd(kvm_ioctls::Error),
    #[cfg(target_arch = "aarch64")]
    CreateIts(kvm_ioctls::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bus(err) => write!(f, "failed to register PCI bus device: {err}"),
            Self::CreateTransport(err) => write!(f, "failed to create virtio-pci transport: {err}"),
            Self::IrqsExhausted => write!(f, "no more GSIs are available for PCI INTx"),
            Self::PciRoot(err) => write!(f, "failed to register PCI function: {err}"),
            Self::EventFd(err) => write!(f, "failed to create an MSI-X eventfd: {err}"),
            Self::RegisterIrqFd(err) => write!(f, "failed to register an MSI-X irqfd: {err}"),
            #[cfg(target_arch = "aarch64")]
            Self::CreateIts(err) => write!(f, "failed to create the GIC ITS: {err}"),
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
use arch::aarch64::layout::{
    GIC_ITS_SIZE, GIC_ITS_START, PCI_BAR_END, PCI_BAR_START, PCI_ECAM_SIZE, PCI_ECAM_START,
};
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
    msi: Option<Arc<msi::MsiRouter>>,
    next_msi_gsi: u32,
    #[cfg(target_arch = "aarch64")]
    its: Option<kvm_ioctls::DeviceFd>,
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
            msi: None,
            next_msi_gsi: msi::MSI_GSI_BASE,
            #[cfg(target_arch = "aarch64")]
            its: None,
        }
    }

    /// Enables MSI-X, delivered by KVM's in-kernel irqchip, for the functions
    /// added after this call. Not for a split irqchip, whose userspace IOAPIC
    /// owns KVM's routing table: its functions keep INTx.
    #[cfg(target_arch = "x86_64")]
    pub fn enable_msi(&mut self, vm: Arc<VmFd>) {
        self.msi = Some(Arc::new(msi::MsiRouter::new(vm)));
    }

    /// Creates the GIC ITS and enables MSI-X through it for the functions
    /// added after this call. The GIC must be a GICv3, created before.
    #[cfg(target_arch = "aarch64")]
    pub fn enable_its(&mut self, vm: Arc<VmFd>) -> Result<()> {
        let mut device = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_ITS,
            fd: 0,
            flags: 0,
        };
        let its = vm.create_device(&mut device).map_err(Error::CreateIts)?;
        let addr = GIC_ITS_START;
        its.set_device_attr(&kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            attr: u64::from(kvm_bindings::KVM_VGIC_ITS_ADDR_TYPE),
            addr: &addr as *const u64 as u64,
            flags: 0,
        })
        .map_err(Error::CreateIts)?;
        its.set_device_attr(&kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
            addr: 0,
            flags: 0,
        })
        .map_err(Error::CreateIts)?;
        self.its = Some(its);
        self.msi = Some(Arc::new(msi::MsiRouter::new(vm)));
        Ok(())
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
        let msix_vectors: Option<Arc<dyn PciMsiVectors>> = match &self.msi {
            Some(router) => {
                // One for the configuration, and one for each queue.
                let count = device.lock().unwrap().queue_config().len() as u32 + 1;
                // The ITS tells functions apart by their requester ID.
                #[cfg(target_arch = "aarch64")]
                let devid = Some(u32::from(address.device) << 3 | u32::from(address.function));
                #[cfg(target_arch = "x86_64")]
                let devid = None;
                let vectors =
                    msi::KvmMsiVectors::new(&vm, router.clone(), self.next_msi_gsi, devid, count)?;
                self.next_msi_gsi += count;
                Some(Arc::new(vectors))
            }
            None => None,
        };
        let mut transport = VirtioPciTransport::new(
            guest_memory,
            device,
            irq as u8,
            intx_line,
            bar_base as u32,
            msix_vectors,
        )
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
            its: self.its.as_ref().map(|_| (GIC_ITS_START, GIC_ITS_SIZE)),
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

/// MSI-X delivery through KVM: one router owns the GSI routing table for all
/// functions, and each function has its own vectors.
mod msi {
    use std::collections::BTreeMap;
    use std::io;
    use std::sync::{Arc, Mutex};

    #[cfg(target_arch = "aarch64")]
    use arch::aarch64::layout::KVM_LAST_SPI;
    use devices::pci::PciMsiVectors;
    use kvm_bindings::{
        KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQ_ROUTING_MSI, KVM_MSI_VALID_DEVID, KvmIrqRouting,
        kvm_irq_routing_entry, kvm_irq_routing_entry__bindgen_ty_1, kvm_irq_routing_irqchip,
        kvm_irq_routing_msi, kvm_irq_routing_msi__bindgen_ty_1,
    };
    #[cfg(target_arch = "x86_64")]
    use kvm_bindings::{KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE};
    use kvm_ioctls::VmFd;
    use utils::eventfd::{EFD_NONBLOCK, EventFd};

    use super::{Error, Result};

    /// The first GSI for MSIs, after the IOAPIC's 24 pins.
    #[cfg(target_arch = "x86_64")]
    pub const MSI_GSI_BASE: u32 = 24;
    /// The first GSI for MSIs, after the GIC's SPIs.
    #[cfg(target_arch = "aarch64")]
    pub const MSI_GSI_BASE: u32 = KVM_LAST_SPI + 1;

    fn irqchip_route(gsi: u32, irqchip: u32, pin: u32) -> kvm_irq_routing_entry {
        kvm_irq_routing_entry {
            gsi,
            type_: KVM_IRQ_ROUTING_IRQCHIP,
            u: kvm_irq_routing_entry__bindgen_ty_1 {
                irqchip: kvm_irq_routing_irqchip { irqchip, pin },
            },
            ..Default::default()
        }
    }

    /// KVM's default routes for the GIC, which setting the table would
    /// otherwise drop: a GSI for each SPI.
    #[cfg(target_arch = "aarch64")]
    fn default_routes() -> Vec<kvm_irq_routing_entry> {
        (0..=KVM_LAST_SPI)
            .map(|pin| irqchip_route(pin, 0, pin))
            .collect()
    }

    /// KVM's default routes for the in-kernel irqchip, which setting the
    /// table would otherwise drop: the IOAPIC's 24 pins, and the two PICs'
    /// 8 pins each for the first 16.
    #[cfg(target_arch = "x86_64")]
    fn default_routes() -> Vec<kvm_irq_routing_entry> {
        let mut routes = Vec::new();
        for gsi in 0..24 {
            if gsi < 16 {
                let pic = if gsi < 8 {
                    KVM_IRQCHIP_PIC_MASTER
                } else {
                    KVM_IRQCHIP_PIC_SLAVE
                };
                routes.push(irqchip_route(gsi, pic, gsi % 8));
            }
            routes.push(irqchip_route(gsi, KVM_IRQCHIP_IOAPIC, gsi));
        }
        routes
    }

    /// KVM's GSI routing table: the default routes, plus an MSI route for
    /// each vector the guest has programmed. KVM replaces the whole table on
    /// each update, so all of it is kept here.
    pub struct MsiRouter {
        vm: Arc<VmFd>,
        routes: Mutex<BTreeMap<u32, kvm_irq_routing_entry>>,
    }

    impl MsiRouter {
        pub fn new(vm: Arc<VmFd>) -> Self {
            Self {
                vm,
                routes: Mutex::new(BTreeMap::new()),
            }
        }

        /// Routes `gsi` to the MSI message (address, data), or removes its
        /// route with `None`. `devid` is the sender's device ID, where the
        /// interrupt controller tells devices apart (the GIC ITS).
        fn set(&self, gsi: u32, devid: Option<u32>, message: Option<(u64, u32)>) -> io::Result<()> {
            let mut routes = self.routes.lock().unwrap();
            match message {
                Some((address, data)) => {
                    routes.insert(
                        gsi,
                        kvm_irq_routing_entry {
                            gsi,
                            type_: KVM_IRQ_ROUTING_MSI,
                            flags: if devid.is_some() {
                                KVM_MSI_VALID_DEVID
                            } else {
                                0
                            },
                            u: kvm_irq_routing_entry__bindgen_ty_1 {
                                msi: kvm_irq_routing_msi {
                                    address_lo: address as u32,
                                    address_hi: (address >> 32) as u32,
                                    data,
                                    __bindgen_anon_1: kvm_irq_routing_msi__bindgen_ty_1 {
                                        devid: devid.unwrap_or(0),
                                    },
                                },
                            },
                            ..Default::default()
                        },
                    );
                }
                None => {
                    routes.remove(&gsi);
                }
            }
            let mut entries = default_routes();
            entries.extend(routes.values().copied());
            let routing = KvmIrqRouting::from_entries(&entries)
                .map_err(|_| io::Error::other("too many interrupt routes"))?;
            self.vm
                .set_gsi_routing(&routing)
                .map_err(|err| io::Error::from_raw_os_error(err.errno()))
        }
    }

    /// A function's MSI-X vectors: one GSI each from `gsi_base`, signalled
    /// through an irqfd and routed by the router.
    pub struct KvmMsiVectors {
        router: Arc<MsiRouter>,
        gsi_base: u32,
        devid: Option<u32>,
        events: Vec<EventFd>,
    }

    impl KvmMsiVectors {
        pub fn new(
            vm: &VmFd,
            router: Arc<MsiRouter>,
            gsi_base: u32,
            devid: Option<u32>,
            count: u32,
        ) -> Result<Self> {
            let events = (0..count)
                .map(|vector| {
                    let event = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?;
                    vm.register_irqfd(&event, gsi_base + vector)
                        .map_err(Error::RegisterIrqFd)?;
                    Ok(event)
                })
                .collect::<Result<_>>()?;
            Ok(Self {
                router,
                gsi_base,
                devid,
                events,
            })
        }
    }

    impl PciMsiVectors for KvmMsiVectors {
        fn count(&self) -> u16 {
            self.events.len() as u16
        }

        fn route(&self, vector: u16, message: Option<(u64, u32)>) -> io::Result<()> {
            self.router
                .set(self.gsi_base + u32::from(vector), self.devid, message)
        }

        fn signal(&self, vector: u16) -> io::Result<()> {
            match self.events.get(usize::from(vector)) {
                Some(event) => event.write(1),
                None => Ok(()),
            }
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
