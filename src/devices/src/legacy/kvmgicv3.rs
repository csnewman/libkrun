// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;

use crate::Error as DeviceError;
use crate::bus::BusDevice;
use crate::legacy::gic::GICDevice;
use crate::legacy::irqchip::IrqChipT;

use kvm_ioctls::{DeviceFd, Error, VmFd};
use utils::eventfd::EventFd;

const KVM_VGIC_V3_BASE_SIZE: u64 = 0x0001_0000;

// Device trees specific constants
const ARCH_GIC_V3_MAINT_IRQ: u32 = 9;

pub struct KvmGicV3 {
    device_fd: DeviceFd,

    /// GIC device properties, to be used for setting up the fdt entry
    properties: [u64; 4],

    /// Number of CPUs handled by the device
    vcpu_count: u64,
}

impl KvmGicV3 {
    pub fn new(vm: &VmFd, vcpu_count: u64) -> Result<Self, Error> {
        let dist_size = KVM_VGIC_V3_BASE_SIZE;
        let dist_addr = arch::MMIO_MEM_START - dist_size;
        let redist_size = 2 * dist_size;
        let redists_size = redist_size * vcpu_count;
        let redists_addr = dist_addr - redists_size;

        let mut gic_device = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
            fd: 0,
            flags: 0,
        };
        let device_fd = vm.create_device(&mut gic_device)?;

        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            attr: u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_DIST),
            addr: &dist_addr as *const u64 as u64,
            flags: 0,
        };
        device_fd.set_device_attr(&attr)?;

        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            attr: u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_REDIST),
            addr: &redists_addr as *const u64 as u64,
            flags: 0,
        };
        device_fd.set_device_attr(&attr)?;

        let nr_irqs: u32 = arch::aarch64::layout::IRQ_MAX - arch::aarch64::layout::IRQ_BASE + 1;
        let nr_irqs_ptr = &nr_irqs as *const u32;
        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            attr: 0,
            addr: nr_irqs_ptr as u64,
            flags: 0,
        };
        device_fd.set_device_attr(&attr)?;

        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
            addr: 0,
            flags: 0,
        };
        device_fd.set_device_attr(&attr)?;

        Ok(Self {
            device_fd,
            properties: [dist_addr, dist_size, redists_addr, redists_size],
            vcpu_count,
        })
    }
}

impl IrqChipT for KvmGicV3 {
    fn get_mmio_addr(&self) -> u64 {
        0
    }

    fn get_mmio_size(&self) -> u64 {
        0
    }

    fn set_irq(
        &self,
        _irq_line: Option<u32>,
        interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError> {
        if let Some(interrupt_evt) = interrupt_evt {
            if let Err(e) = interrupt_evt.write(1) {
                error!("Failed to signal used queue: {e:?}");
                return Err(DeviceError::FailedSignalingUsedQueue(e));
            }
        } else {
            error!("EventFd not set up for irq line");
            return Err(DeviceError::FailedSignalingUsedQueue(io::Error::new(
                io::ErrorKind::NotFound,
                "EventFd not set up for irq line".to_string(),
            )));
        }
        Ok(())
    }

    fn save_state(&self, mpidrs: &[u64]) -> Result<Vec<u8>, DeviceError> {
        let gic = GicAccess(&self.device_fd);
        // LPIs' pending bits go into the guest's own pending tables, which the
        // snapshot's memory image carries.
        gic.ctrl(kvm_bindings::KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES)
            .map_err(snapshot_err("saving the LPI pending tables"))?;

        let typer = gic
            .get(DIST, 0, GICD_TYPER)
            .map_err(snapshot_err("GICD_TYPER"))?;
        let irqs = 32 * ((typer & 0x1f) + 1);
        let mut saved = GicSnapshot {
            irqs,
            dist: Vec::new(),
            levels: Vec::new(),
            redists: Vec::new(),
        };
        for &offset in GICD_GLOBAL {
            saved.dist.push(gic.save(DIST, 0, offset, None)?);
        }
        for &(set, clear, bits) in GICD_IRQ_REGS {
            for offset in (4 * bits..irqs * bits / 8).step_by(4) {
                saved
                    .dist
                    .push(gic.save(DIST, 0, set + offset, clear.map(|c| c + offset))?);
            }
        }
        for intid in (32..irqs).step_by(32) {
            let attr = (u64::from(kvm_bindings::VGIC_LEVEL_INFO_LINE_LEVEL)
                << kvm_bindings::KVM_DEV_ARM_VGIC_LINE_LEVEL_INFO_SHIFT)
                | u64::from(intid);
            let level = gic
                .get_attr(kvm_bindings::KVM_DEV_ARM_VGIC_GRP_LEVEL_INFO, attr)
                .map_err(snapshot_err("line levels"))?;
            saved.levels.push((intid, level));
        }
        for &mpidr in mpidrs {
            let affinity = vgic_affinity(mpidr);
            let mut redist = RedistSnapshot {
                mpidr,
                regs: Vec::new(),
                icc: Vec::new(),
            };
            for &(set, clear) in GICR_REGS {
                redist.regs.push(gic.save(REDIST, affinity, set, clear)?);
            }
            let ctlr = gic
                .get_sysreg(affinity, ICC_CTLR_EL1)
                .map_err(snapshot_err("ICC_CTLR_EL1"))?;
            for reg in icc_regs(ctlr) {
                let value = gic
                    .get_sysreg(affinity, reg)
                    .map_err(snapshot_err("ICC system register"))?;
                redist.icc.push((reg, value));
            }
            saved.redists.push(redist);
        }
        bincode::encode_to_vec(&saved, bincode::config::standard())
            .map_err(|e| DeviceError::Snapshot(e.to_string()))
    }

    fn restore_state(&self, mpidrs: &[u64], state: &[u8]) -> Result<(), DeviceError> {
        let (saved, _): (GicSnapshot, _) =
            bincode::decode_from_slice(state, bincode::config::standard())
                .map_err(|e| DeviceError::Snapshot(format!("GIC state: {e}")))?;
        let gic = GicAccess(&self.device_fd);
        let typer = gic
            .get(DIST, 0, GICD_TYPER)
            .map_err(snapshot_err("GICD_TYPER"))?;
        if 32 * ((typer & 0x1f) + 1) != saved.irqs {
            return Err(DeviceError::Snapshot(format!(
                "GIC state has {} interrupts, the GIC {}",
                saved.irqs,
                32 * ((typer & 0x1f) + 1)
            )));
        }
        let saved_mpidrs: Vec<u64> = saved.redists.iter().map(|r| r.mpidr).collect();
        if saved_mpidrs != mpidrs {
            return Err(DeviceError::Snapshot("GIC state is for other vCPUs".into()));
        }

        // The distributor's control first: whether affinity routing is on
        // decides how the rest is read.
        let (globals, irq_regs) = saved.dist.split_at(GICD_GLOBAL.len());
        for reg in globals {
            gic.restore(DIST, 0, reg)?;
        }
        for redist in &saved.redists {
            let affinity = vgic_affinity(redist.mpidr);
            for reg in &redist.regs {
                gic.restore(REDIST, affinity, reg)?;
            }
        }
        for &(intid, level) in &saved.levels {
            let attr = (u64::from(kvm_bindings::VGIC_LEVEL_INFO_LINE_LEVEL)
                << kvm_bindings::KVM_DEV_ARM_VGIC_LINE_LEVEL_INFO_SHIFT)
                | u64::from(intid);
            gic.set_attr(kvm_bindings::KVM_DEV_ARM_VGIC_GRP_LEVEL_INFO, attr, level)
                .map_err(snapshot_err("line levels"))?;
        }
        for reg in irq_regs {
            gic.restore(DIST, 0, reg)?;
        }
        for redist in &saved.redists {
            let affinity = vgic_affinity(redist.mpidr);
            for &(reg, value) in &redist.icc {
                gic.set_sysreg(affinity, reg, value)
                    .map_err(snapshot_err("ICC system register"))?;
            }
        }
        Ok(())
    }
}

const DIST: u32 = kvm_bindings::KVM_DEV_ARM_VGIC_GRP_DIST_REGS;
const REDIST: u32 = kvm_bindings::KVM_DEV_ARM_VGIC_GRP_REDIST_REGS;

const GICD_TYPER: u32 = 0x0004;

/// Distributor registers that aren't per interrupt, restored first.
const GICD_GLOBAL: &[u32] = &[
    0x0000, // GICD_CTLR
];

/// Per-interrupt distributor registers, for the SPIs: `(set, clear, bits per
/// interrupt)`. A register with a clear counterpart is restored by clearing
/// what was clear, then setting what was set.
const GICD_IRQ_REGS: &[(u32, Option<u32>, u32)] = &[
    (0x0080, None, 1),         // GICD_IGROUPR
    (0x0D00, None, 1),         // GICD_IGRPMODR
    (0x0400, None, 8),         // GICD_IPRIORITYR
    (0x0C00, None, 2),         // GICD_ICFGR
    (0x6000, None, 64),        // GICD_IROUTER
    (0x0200, Some(0x0280), 1), // GICD_ISPENDR, GICD_ICPENDR
    (0x0100, Some(0x0180), 1), // GICD_ISENABLER, GICD_ICENABLER
    (0x0300, Some(0x0380), 1), // GICD_ISACTIVER, GICD_ICACTIVER
];

/// Redistributor registers, in restore order: the LPI tables before
/// GICR_CTLR, which may enable LPIs; then the SGIs' and PPIs' state.
const GICR_REGS: &[(u32, Option<u32>)] = &[
    (0x0070, None),  // GICR_PROPBASER, low
    (0x0074, None),  // GICR_PROPBASER, high
    (0x0078, None),  // GICR_PENDBASER, low
    (0x007C, None),  // GICR_PENDBASER, high
    (0x0000, None),  // GICR_CTLR
    (0x0014, None),  // GICR_WAKER
    (0x10080, None), // GICR_IGROUPR0
    (0x10D00, None), // GICR_IGRPMODR0
    (0x10400, None), // GICR_IPRIORITYR0..
    (0x10404, None),
    (0x10408, None),
    (0x1040C, None),
    (0x10410, None),
    (0x10414, None),
    (0x10418, None),
    (0x1041C, None),
    (0x10C00, None),          // GICR_ICFGR0
    (0x10C04, None),          // GICR_ICFGR1
    (0x10200, Some(0x10280)), // GICR_ISPENDR0, GICR_ICPENDR0
    (0x10100, Some(0x10180)), // GICR_ISENABLER0, GICR_ICENABLER0
    (0x10300, Some(0x10380)), // GICR_ISACTIVER0, GICR_ICACTIVER0
];

/// A system register's encoding, as KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS names it.
const fn sysreg(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
    (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2
}

const ICC_SRE_EL1: u64 = sysreg(3, 0, 12, 12, 5);
const ICC_CTLR_EL1: u64 = sysreg(3, 0, 12, 12, 4);

/// The CPU interface's registers, in restore order: ICC_SRE_EL1 and
/// ICC_CTLR_EL1 first, and as many active priority registers as the
/// interface has priority bits for.
fn icc_regs(ctlr: u64) -> Vec<u64> {
    let mut regs = vec![
        ICC_SRE_EL1,
        ICC_CTLR_EL1,
        sysreg(3, 0, 12, 12, 6), // ICC_IGRPEN0_EL1
        sysreg(3, 0, 12, 12, 7), // ICC_IGRPEN1_EL1
        sysreg(3, 0, 4, 6, 0),   // ICC_PMR_EL1
        sysreg(3, 0, 12, 8, 3),  // ICC_BPR0_EL1
        sysreg(3, 0, 12, 12, 3), // ICC_BPR1_EL1
    ];
    let pri_bits = ((ctlr >> 8) & 0x7) + 1;
    let apr = match pri_bits {
        7 => 4,
        6 => 2,
        _ => 1,
    };
    for n in 0..apr {
        regs.push(sysreg(3, 0, 12, 8, 4 + n)); // ICC_AP0R<n>_EL1
    }
    for n in 0..apr {
        regs.push(sysreg(3, 0, 12, 9, n)); // ICC_AP1R<n>_EL1
    }
    regs
}

/// An MPIDR's affinity, placed where the VGIC's attributes take it.
fn vgic_affinity(mpidr: u64) -> u64 {
    let aff3 = (mpidr >> 32) & 0xff;
    let aff210 = mpidr & 0xff_ffff;
    ((aff3 << 24) | aff210) << 32
}

#[derive(bincode::Encode, bincode::Decode)]
struct GicSnapshot {
    irqs: u32,
    /// `(set, clear, value)`, in restore order; `clear` is 0 for a register
    /// without a clear counterpart.
    dist: Vec<(u32, u32, u32)>,
    /// `(first interrupt, levels)`, for the SPIs.
    levels: Vec<(u32, u32)>,
    redists: Vec<RedistSnapshot>,
}

#[derive(bincode::Encode, bincode::Decode)]
struct RedistSnapshot {
    mpidr: u64,
    regs: Vec<(u32, u32, u32)>,
    icc: Vec<(u64, u64)>,
}

fn snapshot_err(what: &'static str) -> impl Fn(Error) -> DeviceError {
    move |e| DeviceError::Snapshot(format!("GIC {what}: {e}"))
}

struct GicAccess<'a>(&'a DeviceFd);

impl GicAccess<'_> {
    fn get_attr(&self, group: u32, attr: u64) -> Result<u32, Error> {
        let mut value = 0u32;
        let mut attr = kvm_bindings::kvm_device_attr {
            group,
            attr,
            addr: &mut value as *mut u32 as u64,
            flags: 0,
        };
        // SAFETY: `addr` points at a u32 that outlives the call, which is what
        // these groups write.
        unsafe { self.0.get_device_attr(&mut attr) }?;
        Ok(value)
    }

    fn set_attr(&self, group: u32, attr: u64, value: u32) -> Result<(), Error> {
        self.0.set_device_attr(&kvm_bindings::kvm_device_attr {
            group,
            attr,
            addr: &value as *const u32 as u64,
            flags: 0,
        })
    }

    fn get(&self, group: u32, affinity: u64, offset: u32) -> Result<u32, Error> {
        self.get_attr(group, affinity | u64::from(offset))
    }

    fn save(
        &self,
        group: u32,
        affinity: u64,
        set: u32,
        clear: Option<u32>,
    ) -> Result<(u32, u32, u32), DeviceError> {
        let value = self
            .get(group, affinity, set)
            .map_err(|e| DeviceError::Snapshot(format!("GIC register {set:#x}: {e}")))?;
        Ok((set, clear.unwrap_or(0), value))
    }

    fn restore(
        &self,
        group: u32,
        affinity: u64,
        &(set, clear, value): &(u32, u32, u32),
    ) -> Result<(), DeviceError> {
        let err = |e: Error| DeviceError::Snapshot(format!("GIC register {set:#x}: {e}"));
        if clear != 0 {
            self.set_attr(group, affinity | u64::from(clear), !value)
                .map_err(err)?;
        }
        self.set_attr(group, affinity | u64::from(set), value)
            .map_err(err)
    }

    fn get_sysreg(&self, affinity: u64, reg: u64) -> Result<u64, Error> {
        let mut value = 0u64;
        let mut attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS,
            attr: affinity | reg,
            addr: &mut value as *mut u64 as u64,
            flags: 0,
        };
        // SAFETY: `addr` points at a u64 that outlives the call, which is what
        // this group writes.
        unsafe { self.0.get_device_attr(&mut attr) }?;
        Ok(value)
    }

    fn set_sysreg(&self, affinity: u64, reg: u64, value: u64) -> Result<(), Error> {
        self.0.set_device_attr(&kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS,
            attr: affinity | reg,
            addr: &value as *const u64 as u64,
            flags: 0,
        })
    }

    fn ctrl(&self, attr: u32) -> Result<(), Error> {
        self.0.set_device_attr(&kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: u64::from(attr),
            addr: 0,
            flags: 0,
        })
    }
}

impl BusDevice for KvmGicV3 {
    fn read(&mut self, _vcpuid: u64, _offset: u64, _data: &mut [u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }

    fn write(&mut self, _vcpuid: u64, _offset: u64, _data: &[u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }
}

impl GICDevice for KvmGicV3 {
    fn device_properties(&self) -> Vec<u64> {
        self.properties.to_vec()
    }

    fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }

    fn fdt_compatibility(&self) -> String {
        "arm,gic-v3".to_string()
    }

    fn fdt_maint_irq(&self) -> u32 {
        ARCH_GIC_V3_MAINT_IRQ
    }

    fn version(&self) -> u32 {
        kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3
    }
}
