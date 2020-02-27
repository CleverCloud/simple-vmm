#![cfg(any(target_arch = "x86", target_arch = "x86_64"))]

use kvm_bindings::{
    kvm_regs, kvm_userspace_memory_region, KVM_MAX_CPUID_ENTRIES, KVM_MEM_LOG_DIRTY_PAGES,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use std::io::Write;
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

pub struct Mmap {
    pub slot: u32,
    pub size: usize,
    pub host_address: usize,
    pub guest_address: usize,
}

pub struct Vm {
    pub vm: VmFd,
    pub vcpu: VcpuFd,
    pub guest_memory_size: usize,
    pub memory: GuestMemoryMmap,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RunResult {
    Hlt,
    Shutdown,
    Port(u16),
    Pause,
}

impl Vm {
    pub fn new(base_size: u64) -> Option<Vm> {
        let kvm = Kvm::new().expect("new kvm failed");
        let vm = kvm.create_vm().expect("new vm failed");

        // initialize guest memory
        let guest_addr = 0x0;
        let mem_size = base_size;
        let gm =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(guest_addr), mem_size as usize)]).unwrap();
        let load_addr = gm.get_host_address(GuestAddress(guest_addr)).unwrap();

        let slot = 0;
        // When initializing the guest memory slot specify the
        // `KVM_MEM_LOG_DIRTY_PAGES` to enable the dirty log.
        let mem_region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: guest_addr,
            memory_size: mem_size as u64,
            userspace_addr: load_addr as u64,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };
        unsafe { vm.set_user_memory_region(mem_region).unwrap() };

        let cpu_id = 0;
        let cpu_count = 1;
        //vm.create_irq_chip().unwrap();
        let vcpu = vm.create_vcpu(cpu_id).expect("new vcpu failed");
        println!("created vm with mem_size: {:x?}", mem_size);

        let mut kvm_cpuid = kvm.get_emulated_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
        //setup_cpuid(cpu_id=0, nbr_cpus=1)
        // let kvm_cpuid = kvm.get_supportd_cpuid
        // filter_cpuid(cpu_id, nrcpis, &mut kvm_cpuid);

        // Update the CPUID entries to disable the EPB feature.
        const ECX_EPB_SHIFT: u32 = 3;
        {
            let entries = kvm_cpuid.as_mut_slice();
            for entry in entries.iter_mut() {
                match entry.function {
                    1 => {
                        // X86 hypervisor feature
                        if entry.index == 0 {
                            entry.ecx |= 1u32 << ECX_HYPERVISOR_SHIFT;
                        }
                        entry.ebx = ((cpu_id as u32) << EBX_CPUID_SHIFT) as u32
                            | (EBX_CLFLUSH_CACHELINE << EBX_CLFLUSH_SIZE_SHIFT);
                        if cpu_count > 1 {
                            entry.ebx |= (cpu_count as u32) << EBX_CPU_COUNT_SHIFT;
                            entry.edx |= 1u32 << EDX_HTT_SHIFT;
                        }
                    }
                    2 | 0x80000005 | 0x80000006 => unsafe {
                        host_cpuid(
                            entry.function,
                            0,
                            &mut entry.eax as *mut u32,
                            &mut entry.ebx as *mut u32,
                            &mut entry.ecx as *mut u32,
                            &mut entry.edx as *mut u32,
                        );
                    },
                    4 => {
                        unsafe {
                            host_cpuid(
                                entry.function,
                                entry.index,
                                &mut entry.eax as *mut u32,
                                &mut entry.ebx as *mut u32,
                                &mut entry.ecx as *mut u32,
                                &mut entry.edx as *mut u32,
                            );
                        }
                        entry.eax &= !0xFC000000;
                    }
                    6 => {
                        // Clear X86 EPB feature.  No frequency selection in the hypervisor.
                        entry.ecx &= !(1u32 << ECX_EPB_SHIFT);
                    }
                    _ => (),
                }
            }
        }

        //vcpu.set_cpuid
        let _cpuid_res = vcpu.set_cpuid2(&kvm_cpuid).unwrap();
        println!("setup cpuid: {:?}", _cpuid_res);

        let _msrs_res = super::x86::setup_msrs(&vcpu).unwrap();
        println!("setup_msrs: {:?}", _msrs_res);

        let _sregs_res = super::x86::setup_sregs(&gm, &vcpu);
        println!("setup_sregs: {:?}", _sregs_res);
        let _fpu_res = super::x86::setup_fpu(&vcpu);
        println!("setup_fpu: {:?}", _fpu_res);
        let _xcrs_res = super::x86::setup_xcrs(&vcpu);
        println!("setup_xcrs: {:?}", _xcrs_res);

        Some(Vm {
            vm,
            vcpu,
            guest_memory_size: mem_size as usize,
            memory: gm,
        })
    }
    pub fn write_slice(&mut self, buf: &[u8], address: u64) -> Option<usize> {
        self.memory.write(buf, GuestAddress(address)).ok()
    }

    pub fn read_slice(&self, buf: &mut [u8], address: u64) -> Option<usize> {
        self.memory.read(buf, GuestAddress(address)).ok()
    }

    pub fn write_from_vm<W>(&self, address: u64, size: usize, w: &mut W) -> Option<()>
    where
        W: Write,
    {
        self.memory
            .write_to(GuestAddress(address), w, size)
            .ok()
            .map(|_| ())
    }
    /*

    pub fn load_code(&mut self, code: &[u8], address: u64) {
      let mem_map = MemoryMapping::new(4096).unwrap();
      let _res = mem_map.write_slice(&code[..], 0).unwrap();
      let _slot:u32 = self.vm.add_device_memory(
          GuestAddress(address),
          mem_map,
          true,
          true).expect("error adding code to memory");
    }

    pub fn load_data(&mut self, data: &[u8], address: u64) {
      let mem_map = MemoryMapping::new(4096).unwrap();
      let _res = mem_map.write_slice(&data[..], 0).unwrap();
      self.vm.add_device_memory(
          GuestAddress(address),
          mem_map,
          false,
          true).expect("error adding code to memory");
    }
    */

    pub fn run(&mut self, address: u64) -> Result<RunResult, String> {
        let mut vcpu_regs: kvm_regs = self.vcpu.get_regs().unwrap(); //unsafe { std::mem::zeroed() };
        vcpu_regs.rip = address;
        vcpu_regs.rflags = 2;
        self.vcpu.set_regs(&vcpu_regs).expect("set regs failed");

        self.start()
    }

    pub fn start(&mut self) -> Result<RunResult, String> {
        loop {
            match self.vcpu.run() {
                Ok(VcpuExit::IoOut(
                    port,
                    //data,
                    ..,
                )) => {
                    if port == 0x10 {
                        let e = kvm_ioctls::Error::last();
                        println!("port 0x10: errno = {:?}", e);
                        let ev = self.vcpu.get_vcpu_events();
                        println!("port 0x10: vcpu events = {:x?}", ev);
                    }

                    return Ok(RunResult::Port(port));
                }
                Ok(VcpuExit::Hlt) => {
                    let e = kvm_ioctls::Error::last();
                    println!("hlt: errno = {:?}", e);
                    let ev = self.vcpu.get_vcpu_events();
                    println!("hlt: vcpu events = {:x?}", ev);
                    return Ok(RunResult::Hlt);
                }
                Ok(VcpuExit::Shutdown) => {
                    let e = kvm_ioctls::Error::last();
                    println!("shutdown: errno = {:?}", e);
                    let ev = self.vcpu.get_vcpu_events();
                    println!("shutdown: vcpu events = {:x?}", ev);
                    return Ok(RunResult::Shutdown);
                }
                Ok(r) => {
                    let regs = self.vcpu.get_regs().unwrap();
                    //println!("rax: {}, rip: {:x?}", regs.rax, regs.rip);
                    return Err(format!(
                        "unexpected exit reason: {:?}, rip = {:x?}, rax = {:x?}, registers: {:x?}",
                        r, regs.rip, regs.rax, regs
                    ));
                }
                Err(e) => {
                    let regs = self.vcpu.get_regs().unwrap();

                    if e == kvm_ioctls::Error::new(4) {
                        return Ok(RunResult::Pause);
                    } else {
                        return Err(format!("error in vcpu run: {} rip: {:?}", e, regs.rip));
                    }
                }
            }
        }
    }
}

// CPUID bits in ebx, ecx, and edx.
const EBX_CLFLUSH_CACHELINE: u32 = 8; // Flush a cache line size.
const EBX_CLFLUSH_SIZE_SHIFT: u32 = 8; // Bytes flushed when executing CLFLUSH.
const EBX_CPU_COUNT_SHIFT: u32 = 16; // Index of this CPU.
const EBX_CPUID_SHIFT: u32 = 24; // Index of this CPU.
const ECX_EPB_SHIFT: u32 = 3; // "Energy Performance Bias" bit.
const ECX_HYPERVISOR_SHIFT: u32 = 31; // Flag to be set when the cpu is running on a hypervisor.
const EDX_HTT_SHIFT: u32 = 28; // Hyper Threading Enabled.

extern "C" {
    fn host_cpuid(
        func: u32,
        func2: u32,
        rEax: *mut u32,
        rEbx: *mut u32,
        rEcx: *mut u32,
        rEdx: *mut u32,
    ) -> ();
}

#[test]
fn x86() {
    let mut vm = Vm::new(0x10000).unwrap();
    let code = [
        0xB8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
        0xf4, // hlt
    ];

    println!("load code: {:x?}", vm.write_slice(&code, 0x4000));
    vm.run(0x4000).unwrap();
    let regs = vm.vcpu.get_regs().unwrap();
    println!("rax: {}, rip: {:x?}", regs.rax, regs.rip);
    assert_eq!(regs.rip, 0x4006);
    assert_eq!(regs.rax, 0x12345678);
}

#[test]
fn x86_64() {
    let mut vm = Vm::new(0x205000).unwrap();
    let code = [
        0x48, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34,
        0x12, // mov eax, 0x1234567812345678
        0xf4, // hlt
    ];

    println!("load code: {:x?}", vm.write_slice(&code, 0x104000));
    vm.run(0x104000).unwrap();
    let regs = vm.vcpu.get_regs().unwrap();
    println!("rax: {}, rip: {:x?}", regs.rax, regs.rip);
    assert_eq!(regs.rax, 0x1234567812345678);
    assert_eq!(regs.rip, 0x10400B);
}

#[test]
fn wasm_x86_64() {
    let mut vm = Vm::new(0x205000).unwrap();
    let hostcall = [
        0xe7, 0x10, // out 0x10
        0xe7, 0x2a, // out 0x2a
        0xc3, // ret
    ];
    println!("load hostcall: {:x?}", vm.write_slice(&hostcall, 0x1000));

    /*let code = [
      0x48, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x1234567812345678
      0xf4 // hlt
    ];*/
    let code = [
        0x40, 0x55, // rex push rbp
        0x48, 0x89, 0xe5, // mov rbp, rsp
        0x40, 0xb8, 0x00, 0x00, 0x10, 0x00, // rex mov eax, 0x100000
        0x40, 0xb9, 0x0f, 0x00, 0x00, 0x00, // rex mov ecx, 0xf
        0x48, 0xba, 0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rdx, 0x1002
        0x40, 0x89, 0xc7, // rex mov edi, eax
        0x48, 0x89, 0xce, // mov rsi, rcx
        0x40, 0xff, 0xd2, // rex call rdx
        0x40, 0x5d, // rex pop rbp
        0xc3, // ret
    ];
    let code_len = code.len();
    //let code_len = 17;
    //let code_len = 39;

    println!(
        "load code: {:x?}",
        vm.write_slice(&code[..code_len], 0x104000)
    );
    let hlt = [0xf4];
    vm.write_slice(&hlt, (0x104000 + code_len) as u64);

    let stack_offset = 0x103000;
    let stack_head = [0x00, 0x10, 0x00, 0x00];
    //vm.write_slice(&stack_head, stack_offset - 8);
    vm.write_slice(&stack_head, stack_offset);

    let mut regs = vm.vcpu.get_regs().unwrap();
    regs.rsp = stack_offset;
    regs.rbp = stack_offset;
    regs.rflags = 2;
    vm.vcpu.set_regs(&regs).unwrap();

    assert_eq!(vm.run(0x104000), Ok(RunResult::Port(42)));
    let regs = vm.vcpu.get_regs().unwrap();
    println!("regs: {:x?}", regs);
    assert_eq!(regs.rdi, 0x100000);
    assert_eq!(regs.rsi, 0xf);
    assert_eq!(regs.rip, 0x1002);

    println!("vm restart: {:?}", vm.start());
    let regs = vm.vcpu.get_regs().unwrap();
    println!("rax: {:x?}, rip: {:x?}", regs.rax, regs.rip);
    println!("regs: {:x?}", regs);
    assert_eq!(regs.rip, 0x1000);
}

#[test]
fn xmm() {
    let mut vm = Vm::new(0x205000).unwrap();

    let hostcall = [
        0xe7, 0x10, // out 0x10
        0xe7, 0x2a, // out 0x2a
        0xc3, // ret
    ];
    println!("load hostcall: {:x?}", vm.write_slice(&hostcall, 0x1000));

    let code = [
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0,
        0xff, // movabs rax,0xfff0000000000000
        //0x66, 0x48, 0x0f, 0x6e, 0xc0, //          movq   xmm0,rax
        0xc5, 0xf9, 0x6e, 0xc0,             // vmovd  xmm0,eax
        0x0f, 0x28, 0xc8,             //   movaps xmm1,xmm0
        0x48, 0xB9, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34,
        0x12, // mov ecx, 0x1234567812345678
        0xf4, // hlt
    ];
    let code_len = code.len();
    println!(
        "load code: {:x?}",
        vm.write_slice(&code[..code_len], 0x104000)
    );
    let hlt = [0xf4];
    vm.write_slice(&hlt, (0x104000 + code_len) as u64);

    let stack_offset = 0x103000;
    let stack_head = [0x00, 0x10, 0x00, 0x00];
    vm.write_slice(&stack_head, stack_offset);

    let mut regs = vm.vcpu.get_regs().unwrap();
    regs.rsp = stack_offset;
    regs.rbp = stack_offset;
    regs.rflags = 2;
    vm.vcpu.set_regs(&regs).unwrap();

    let res = vm.run(0x104000);
    println!("vm run: {:?}", res);
    let regs = vm.vcpu.get_regs().unwrap();
    println!("regs     : {:x?}", regs);
    let events = vm.vcpu.get_vcpu_events().unwrap();
    println!("events   : {:x?}", events);
    let debugregs = vm.vcpu.get_debug_regs().unwrap();
    println!("debugregs: {:x?}", debugregs);
    let fpu = vm.vcpu.get_fpu().unwrap();
    println!("fpu: {:x?}", fpu);
    println!("fpu.xmm[0]: {:x?}", fpu.xmm[0]);
    println!("fpu.xmm[1]: {:x?}", fpu.xmm[1]);

    assert_eq!(res, Ok(RunResult::Hlt));
    assert_eq!(regs.rax, 0xFFF0000000000000);
    assert_eq!(regs.rcx, 0x1234567812345678);
    assert_eq!(
        &fpu.xmm[0][..],
        [0, 0, 0, 0, 0, 0, 0xF0, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        &fpu.xmm[1][..],
        [0, 0, 0, 0, 0, 0, 0xF0, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    //assert_eq!(regs.rip, 0x10401a);
}
