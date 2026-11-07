pub mod mmio;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub mod pci;
