use super::gdt;
use kvm_bindings::{kvm_fpu, kvm_msr_entry, kvm_sregs, kvm_xcrs, Msrs};
use kvm_ioctls::VcpuFd;
use std::mem;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory};

/// Configure Model specific registers for x86
///
/// # Arguments
///
/// * `vcpu` - Structure for the vcpu that holds the vcpu fd.
pub fn setup_msrs(vcpu: &VcpuFd) -> Result<(), &'static str> {
    let msrs = create_msr_entries().map_err(|_| "Error::MsrIoctlFailed")?;
    vcpu.set_msrs(&msrs).map_err(|_| "Error::MsrIoctlFailed")?;

    Ok(())
}

fn create_msr_entries() -> Result<Msrs, vmm_sys_util::fam::Error> {
    Msrs::from_entries(&[
        kvm_msr_entry {
            index: super::msr_index::MSR_IA32_SYSENTER_CS,
            data: 0x0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: super::msr_index::MSR_IA32_SYSENTER_ESP,
            data: 0x0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: super::msr_index::MSR_IA32_SYSENTER_EIP,
            data: 0x0,
            ..Default::default()
        },
        // x86_64 specific msrs, we only run on x86_64 not x86
        kvm_msr_entry {
            index: super::msr_index::MSR_STAR,
            data: 0x0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: super::msr_index::MSR_CSTAR,
            data: 0x0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: super::msr_index::MSR_KERNEL_GS_BASE,
            data: 0x0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: super::msr_index::MSR_SYSCALL_MASK,
            data: 0x0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: super::msr_index::MSR_LSTAR,
            data: 0x0,
            ..Default::default()
        },
        // end of x86_64 specific code
        kvm_msr_entry {
            index: super::msr_index::MSR_IA32_TSC,
            data: 0x0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: super::msr_index::MSR_IA32_MISC_ENABLE,
            data: super::msr_index::MSR_IA32_MISC_ENABLE_FAST_STRING as u64,
            ..Default::default()
        },
    ])
}

/// Configures the segment registers and system page tables for a given CPU.
///
/// # Arguments
///
/// * `mem` - The memory that will be passed to the guest.
/// * `vcpu_fd` - The FD returned from the KVM_CREATE_VCPU ioctl.
pub fn setup_sregs<M: GuestMemory>(mem: &M, vcpu: &VcpuFd) -> Result<(), &'static str> {
    let mut sregs: kvm_sregs = vcpu.get_sregs().map_err(|_| "Error::GetSRegsIoctlFailed")?;

    configure_segments_and_sregs(mem, &mut sregs)?;
    setup_page_tables(mem, &mut sregs)?; // TODO(dgreid) - Can this be done once per system instead?

    // enable SSE
    sregs.cr0 &= 0xFFFFFFFB; // clear CR0.EM processor emulation
    sregs.cr0 |= 1 << 1; // set CR0.MP
    sregs.cr4 |= 3 << 9; // set CR4.OSFXSR and CR4.OSXMMEXCPT

    // XSAVE support
    //sregs.cr4 |= 1 << 18;

    vcpu.set_sregs(&sregs)
        .map_err(|_| "Error::SetSRegsIoctlFailed")?;

    Ok(())
}

/// configures xcrs for a given cpu.
///
/// # arguments
///
/// * `vcpu_fd` - the fd returned from the kvm_create_vcpu ioctl.
pub fn setup_xcrs(vcpu: &VcpuFd) -> Result<(), &'static str> {
    let mut xcrs: kvm_xcrs = vcpu.get_xcrs().map_err(|_| "error::GetXcrIoctlFailed")?;

    println!("xcrs[0] before: {:x?}", xcrs.xcrs[0]);

    // activate AVX and AXV-512
    xcrs.xcrs[0].xcr |= 0b11100011;
    println!("xcrs[0] after: {:x?}", xcrs.xcrs[0]);

    vcpu.set_xcrs(&xcrs)
        .map_err(|_| "Error::SetXcrsIoctlFailed")?;

    Ok(())
}

const X86_CR0_PE: u64 = 0x1;
const X86_CR0_PG: u64 = 0x80000000;
const X86_CR4_PAE: u64 = 0x20;

const EFER_LME: u64 = 0x100;
const EFER_LMA: u64 = 0x400;

const BOOT_GDT_OFFSET: u64 = 0x500;
const BOOT_IDT_OFFSET: u64 = 0x520;

const BOOT_GDT_MAX: usize = 4;

fn write_gdt_table<M: GuestMemory>(table: &[u64], guest_mem: &M) -> Result<(), &'static str> {
    let boot_gdt_addr = GuestAddress(BOOT_GDT_OFFSET);
    for (index, entry) in table.iter().enumerate() {
        let addr = guest_mem
            .checked_offset(boot_gdt_addr, index * mem::size_of::<u64>())
            .ok_or("Error::WriteGDTFailure")?;
        guest_mem
            .write_slice(&entry.to_le_bytes(), addr)
            .map_err(|_| "Error::WriteGDTFailure")?;
    }
    Ok(())
}

fn write_idt_value<M: GuestMemory>(val: u64, guest_mem: &M) -> Result<(), &'static str> {
    let boot_idt_addr = GuestAddress(BOOT_IDT_OFFSET);
    guest_mem
        .write_slice(&val.to_le_bytes(), boot_idt_addr)
        .map_err(|_| "Error::WriteIDTFailure")
}

fn configure_segments_and_sregs<M: GuestMemory>(
    mem: &M,
    sregs: &mut kvm_sregs,
) -> Result<(), &'static str> {
    let gdt_table: [u64; BOOT_GDT_MAX as usize] = [
        gdt::gdt_entry(0, 0, 0),            // NULL
        gdt::gdt_entry(0xa09a, 0, 0xfffff), // CODE
        gdt::gdt_entry(0xa092, 0, 0xfffff), // DATA
        gdt::gdt_entry(0x808b, 0, 0xfffff), // TSS
    ];

    let code_seg = gdt::kvm_segment_from_gdt(gdt_table[1], 1);
    let data_seg = gdt::kvm_segment_from_gdt(gdt_table[2], 2);
    let tss_seg = gdt::kvm_segment_from_gdt(gdt_table[3], 3);

    // Write segments
    write_gdt_table(&gdt_table[..], mem)?;
    sregs.gdt.base = BOOT_GDT_OFFSET as u64;
    sregs.gdt.limit = mem::size_of_val(&gdt_table) as u16 - 1;

    write_idt_value(0, mem)?;
    sregs.idt.base = BOOT_IDT_OFFSET as u64;
    sregs.idt.limit = mem::size_of::<u64>() as u16 - 1;

    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;
    sregs.tr = tss_seg;

    /* 64-bit protected mode */
    sregs.cr0 |= X86_CR0_PE;
    sregs.efer |= EFER_LME;

    Ok(())
}

fn setup_page_tables<M: GuestMemory>(mem: &M, sregs: &mut kvm_sregs) -> Result<(), &'static str> {
    // Puts PML4 right after zero page but aligned to 4k.
    let boot_pml4_addr = GuestAddress(0x9000);
    let boot_pdpte_addr = GuestAddress(0xa000);
    let boot_pde_addr = GuestAddress(0xb000);

    // Entry covering VA [0..512GB)
    mem.write_slice(
        &(boot_pdpte_addr.raw_value() as u64 | 0x03).to_le_bytes(),
        boot_pml4_addr,
    )
    .map_err(|_| "Error::WritePML4Address")?;

    // Entry covering VA [0..1GB)
    mem.write_slice(
        &(boot_pde_addr.raw_value() as u64 | 0x03).to_le_bytes(),
        boot_pdpte_addr,
    )
    .map_err(|_| "Error::WritePDPTEAddress")?;

    // 512 2MB entries together covering VA [0..1GB). Note we are assuming
    // CPU supports 2MB pages (/proc/cpuinfo has 'pse'). All modern CPUs do.
    for i in 0..512 {
        mem.write_slice(
            &((i << 21) + 0x83u64).to_le_bytes(),
            boot_pde_addr.unchecked_add(i * 8),
        )
        .map_err(|_| "Error::WritePDEAddress")?;
    }
    sregs.cr3 = boot_pml4_addr.raw_value() as u64;
    sregs.cr4 |= X86_CR4_PAE;
    sregs.cr0 |= X86_CR0_PG;
    sregs.efer |= EFER_LMA; // Long mode is active. Must be auto-enabled with CR0_PG.
    Ok(())
}

/// Configure FPU registers for x86
///
/// # Arguments
///
/// * `vcpu` - Structure for the vcpu that holds the vcpu fd.
pub fn setup_fpu(vcpu: &VcpuFd) -> Result<(), &'static str> {
    let fpu: kvm_fpu = kvm_fpu {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..Default::default()
    };

    vcpu.set_fpu(&fpu).map_err(|_| "Error::FpuIoctlFailed")?;

    Ok(())
}
