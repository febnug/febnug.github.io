const papers = [
  {
    title: "XLATB as a Tiny VM Dispatcher",
    year: "2026",
    status: "draft",
    tags: ["x86_64", "shellcode", "VM"],
    description: "Eksperimen memakai XLATB sebagai dispatcher VM kecil untuk transformasi byte dan eksekusi minimal.",
    paperUrl: "papers/xlatb-tiny-vm.txt",
    pocUrl: "https://github.com/yourname/your-repo"
  },
  {
    title: "Recursive ELF Through memfd",
    year: "2026",
    status: "archived",
    tags: ["ELF", "memfd", "execveat"],
    description: "Catatan tentang ELF yang mengeksekusi layer berikutnya dari memfd tanpa file child permanen.",
    paperUrl: "papers/recursive-elf-memfd.txt",
    pocUrl: "#"
  },
  {
    title: "Syscalls From Corrupted Context",
    year: "2026",
    status: "rejected",
    tags: ["signals", "syscall", "Linux"],
    description: "Draft tentang signal handler, sigaltstack, dan eksekusi syscall setelah konteks sengaja dibuat rusak.",
    paperUrl: "papers/syscalls-corrupted-context.txt",
    pocUrl: "#"
  }
];
