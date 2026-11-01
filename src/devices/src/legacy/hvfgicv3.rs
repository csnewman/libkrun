// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::os::raw::c_void;
use std::sync::LazyLock;

use crate::Error as DeviceError;
use crate::bus::BusDevice;
use crate::legacy::gic::GICDevice;
use crate::legacy::irqchip::IrqChipT;

use hvf::Error;
use hvf::bindings::{
    HV_SUCCESS, hv_gic_config_t, hv_gic_icc_reg_t, hv_gic_icc_reg_t_HV_GIC_ICC_REG_AP0R0_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_AP1R0_EL1, hv_gic_icc_reg_t_HV_GIC_ICC_REG_BPR0_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_BPR1_EL1, hv_gic_icc_reg_t_HV_GIC_ICC_REG_CTLR_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_IGRPEN0_EL1, hv_gic_icc_reg_t_HV_GIC_ICC_REG_IGRPEN1_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_PMR_EL1, hv_gic_icc_reg_t_HV_GIC_ICC_REG_SRE_EL1,
    hv_gic_state_t, hv_ipa_t, hv_return_t, hv_vcpu_t, os_release,
};
use utils::eventfd::EventFd;

// Device trees specific constants
const ARCH_GIC_V3_MAINT_IRQ: u32 = 9;

/// The CPU interface registers a snapshot saves for each vCPU: those the
/// guest writes. The running priority is read-only.
const SAVED_ICC: [hv_gic_icc_reg_t; 9] = [
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_SRE_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_CTLR_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_PMR_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_BPR0_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_BPR1_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_IGRPEN0_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_IGRPEN1_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_AP0R0_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_AP1R0_EL1,
];

pub struct HvfGicBindings {
    hv_gic_create:
        libloading::Symbol<'static, unsafe extern "C" fn(hv_gic_config_t) -> hv_return_t>,
    hv_gic_config_create: libloading::Symbol<'static, unsafe extern "C" fn() -> hv_gic_config_t>,
    hv_gic_config_set_distributor_base:
        libloading::Symbol<'static, unsafe extern "C" fn(hv_gic_config_t, hv_ipa_t) -> hv_return_t>,
    hv_gic_config_set_redistributor_base:
        libloading::Symbol<'static, unsafe extern "C" fn(hv_gic_config_t, hv_ipa_t) -> hv_return_t>,
    hv_gic_get_distributor_size:
        libloading::Symbol<'static, unsafe extern "C" fn(*mut usize) -> hv_return_t>,
    hv_gic_get_redistributor_size:
        libloading::Symbol<'static, unsafe extern "C" fn(*mut usize) -> hv_return_t>,
    hv_gic_set_spi: libloading::Symbol<'static, unsafe extern "C" fn(u32, bool) -> hv_return_t>,
    /// For snapshots, which a GIC without them can't take.
    state: Option<HvfGicStateBindings>,
}

pub struct HvfGicStateBindings {
    hv_gic_state_create: libloading::Symbol<'static, unsafe extern "C" fn() -> hv_gic_state_t>,
    hv_gic_state_get_size: libloading::Symbol<
        'static,
        unsafe extern "C" fn(hv_gic_state_t, *mut usize) -> hv_return_t,
    >,
    hv_gic_state_get_data: libloading::Symbol<
        'static,
        unsafe extern "C" fn(hv_gic_state_t, *mut c_void) -> hv_return_t,
    >,
    hv_gic_set_state:
        libloading::Symbol<'static, unsafe extern "C" fn(*const c_void, usize) -> hv_return_t>,
    hv_gic_get_icc_reg: libloading::Symbol<
        'static,
        unsafe extern "C" fn(hv_vcpu_t, hv_gic_icc_reg_t, *mut u64) -> hv_return_t,
    >,
    hv_gic_set_icc_reg: libloading::Symbol<
        'static,
        unsafe extern "C" fn(hv_vcpu_t, hv_gic_icc_reg_t, u64) -> hv_return_t,
    >,
}

impl HvfGicStateBindings {
    fn load() -> Result<Self, libloading::Error> {
        unsafe {
            Ok(Self {
                hv_gic_state_create: HVF.get(b"hv_gic_state_create")?,
                hv_gic_state_get_size: HVF.get(b"hv_gic_state_get_size")?,
                hv_gic_state_get_data: HVF.get(b"hv_gic_state_get_data")?,
                hv_gic_set_state: HVF.get(b"hv_gic_set_state")?,
                hv_gic_get_icc_reg: HVF.get(b"hv_gic_get_icc_reg")?,
                hv_gic_set_icc_reg: HVF.get(b"hv_gic_set_icc_reg")?,
            })
        }
    }
}

pub struct HvfGicV3 {
    bindings: HvfGicBindings,

    /// GIC device properties, to be used for setting up the fdt entry
    properties: [u64; 4],

    /// Number of CPUs handled by the device
    vcpu_count: u64,
}

static HVF: LazyLock<libloading::Library> = LazyLock::new(|| unsafe {
    libloading::Library::new(
        "/System/Library/Frameworks/Hypervisor.framework/Versions/A/Hypervisor",
    )
    .unwrap()
});

impl HvfGicV3 {
    pub fn new(vcpu_count: u64) -> Result<Self, Error> {
        let bindings = unsafe {
            HvfGicBindings {
                hv_gic_create: HVF.get(b"hv_gic_create").map_err(Error::FindSymbol)?,
                hv_gic_config_create: HVF
                    .get(b"hv_gic_config_create")
                    .map_err(Error::FindSymbol)?,
                hv_gic_config_set_distributor_base: HVF
                    .get(b"hv_gic_config_set_distributor_base")
                    .map_err(Error::FindSymbol)?,
                hv_gic_config_set_redistributor_base: HVF
                    .get(b"hv_gic_config_set_redistributor_base")
                    .map_err(Error::FindSymbol)?,
                hv_gic_get_distributor_size: HVF
                    .get(b"hv_gic_get_distributor_size")
                    .map_err(Error::FindSymbol)?,
                hv_gic_get_redistributor_size: HVF
                    .get(b"hv_gic_get_redistributor_size")
                    .map_err(Error::FindSymbol)?,
                hv_gic_set_spi: HVF.get(b"hv_gic_set_spi").map_err(Error::FindSymbol)?,
                state: HvfGicStateBindings::load().ok(),
            }
        };

        let mut dist_size: usize = 0;
        let ret = unsafe { (bindings.hv_gic_get_distributor_size)(&mut dist_size) };
        if ret != HV_SUCCESS {
            return Err(Error::VmCreate);
        }
        let dist_size = dist_size as u64;

        let mut redist_size: usize = 0;
        let ret = unsafe { (bindings.hv_gic_get_redistributor_size)(&mut redist_size) };
        if ret != HV_SUCCESS {
            return Err(Error::VmCreate);
        }

        let redists_size = redist_size as u64 * vcpu_count;
        let dist_addr = arch::MMIO_MEM_START - dist_size - redists_size;
        let redists_addr = arch::MMIO_MEM_START - redists_size;

        let gic_config = unsafe { (bindings.hv_gic_config_create)() };
        let ret = unsafe { (bindings.hv_gic_config_set_distributor_base)(gic_config, dist_addr) };
        if ret != HV_SUCCESS {
            return Err(Error::VmCreate);
        }

        let ret = unsafe {
            (bindings.hv_gic_config_set_redistributor_base)(
                gic_config,
                arch::MMIO_MEM_START - redists_size,
            )
        };
        if ret != HV_SUCCESS {
            return Err(Error::VmCreate);
        }

        let ret = unsafe { (bindings.hv_gic_create)(gic_config) };
        if ret != HV_SUCCESS {
            return Err(Error::VmCreate);
        }

        Ok(Self {
            bindings,
            properties: [dist_addr, dist_size, redists_addr, redists_size],
            vcpu_count,
        })
    }

    fn state_bindings(&self) -> Result<&HvfGicStateBindings, DeviceError> {
        self.bindings.state.as_ref().ok_or_else(|| {
            DeviceError::Snapshot("this macOS can't save the GIC's state".into())
        })
    }
}

impl IrqChipT for HvfGicV3 {
    fn get_mmio_addr(&self) -> u64 {
        0
    }

    fn get_mmio_size(&self) -> u64 {
        0
    }

    fn set_irq(
        &self,
        irq_line: Option<u32>,
        _interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError> {
        if let Some(irq_line) = irq_line {
            let ret = unsafe { (self.bindings.hv_gic_set_spi)(irq_line, true) };
            if ret != HV_SUCCESS {
                Err(DeviceError::FailedSignalingUsedQueue(
                    std::io::Error::other("HVF returned error when setting SPI"),
                ))
            } else {
                Ok(())
            }
        } else {
            Err(DeviceError::FailedSignalingUsedQueue(io::Error::new(
                io::ErrorKind::InvalidData,
                "IRQ not line configured",
            )))
        }
    }

    fn save_state(&self, _mpidrs: &[u64]) -> Result<Vec<u8>, DeviceError> {
        let b = self.state_bindings()?;
        let failed = || DeviceError::Snapshot("HVF can't save the GIC's state".into());
        // SAFETY: the state object is created, read and released here.
        unsafe {
            let state = (b.hv_gic_state_create)();
            if state.is_null() {
                return Err(failed());
            }
            let mut size = 0;
            let mut data = Vec::new();
            let ret = if (b.hv_gic_state_get_size)(state, &mut size) == HV_SUCCESS {
                data.resize(size, 0);
                (b.hv_gic_state_get_data)(state, data.as_mut_ptr().cast())
            } else {
                !HV_SUCCESS
            };
            os_release(state.cast());
            if ret != HV_SUCCESS {
                return Err(failed());
            }
            Ok(data)
        }
    }

    fn restore_state(&self, _mpidrs: &[u64], state: &[u8]) -> Result<(), DeviceError> {
        let b = self.state_bindings()?;
        // SAFETY: HVF reads `state.len()` bytes from `state`.
        if unsafe { (b.hv_gic_set_state)(state.as_ptr().cast(), state.len()) } != HV_SUCCESS {
            return Err(DeviceError::Snapshot(
                "HVF can't load the GIC's state".into(),
            ));
        }
        Ok(())
    }

    fn save_vcpu_state(&self, vcpuid: u64) -> Result<Vec<(u32, u64)>, DeviceError> {
        let b = self.state_bindings()?;
        SAVED_ICC
            .iter()
            .map(|&reg| {
                let mut val = 0;
                // SAFETY: HVF writes one register's value to `val`.
                match unsafe { (b.hv_gic_get_icc_reg)(vcpuid, reg, &mut val) } {
                    HV_SUCCESS => Ok((u32::from(reg), val)),
                    _ => Err(DeviceError::Snapshot(format!(
                        "HVF can't read GIC CPU interface register {reg}"
                    ))),
                }
            })
            .collect()
    }

    fn restore_vcpu_state(&self, vcpuid: u64, regs: &[(u32, u64)]) -> Result<(), DeviceError> {
        let b = self.state_bindings()?;
        for &(reg, val) in regs {
            // A snapshot is the guest's to write, so it may set only the
            // registers a snapshot saves.
            let Some(&reg) = SAVED_ICC.iter().find(|&&r| u32::from(r) == reg) else {
                return Err(DeviceError::Snapshot(format!(
                    "the snapshot has GIC CPU interface register {reg}"
                )));
            };
            // SAFETY: a plain call with no memory passed.
            if unsafe { (b.hv_gic_set_icc_reg)(vcpuid, reg, val) } != HV_SUCCESS {
                return Err(DeviceError::Snapshot(format!(
                    "HVF can't write GIC CPU interface register {reg}"
                )));
            }
        }
        Ok(())
    }
}

impl BusDevice for HvfGicV3 {
    fn read(&mut self, _vcpuid: u64, _offset: u64, _data: &mut [u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }

    fn write(&mut self, _vcpuid: u64, _offset: u64, _data: &[u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }
}

impl GICDevice for HvfGicV3 {
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
        7
    }
}
