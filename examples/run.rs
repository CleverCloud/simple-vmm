use simple_vmm::Vm;

fn main() {
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
  println!("done!");
}
