const $ = id => document.getElementById(id);
let current = null;
let currentName = 'binary';

const drop = $('dropZone');
const input = $('fileInput');
drop.addEventListener('click', () => input.click());
drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('drag'); });
drop.addEventListener('dragleave', () => drop.classList.remove('drag'));
drop.addEventListener('drop', e => { e.preventDefault(); drop.classList.remove('drag'); if(e.dataTransfer.files[0]) loadFile(e.dataTransfer.files[0]); });
input.addEventListener('change', e => { if(e.target.files[0]) loadFile(e.target.files[0]); });
$('analyzeBtn').addEventListener('click', analyzeRange);
$('saveBtn').addEventListener('click', exportReport);

function loadFile(file){
  currentName = file.name;
  const r = new FileReader();
  r.onload = () => {
    current = new Uint8Array(r.result);
    $('toolbar').classList.remove('hidden');
    $('cards').classList.remove('hidden');
    $('workspace').classList.remove('hidden');
    $('fileMeta').textContent = `${file.name} · ${fmtSize(file.size)} · ${current.length.toLocaleString()} bytes`;
    $('offsetInput').value = preferredEntryOffset(current);
    analyzeRange();
  };
  r.readAsArrayBuffer(file);
}

function analyzeRange(){
  if(!current) return;
  const off = parseNum($('offsetInput').value);
  const len = Math.max(1, parseNum($('lenInput').value));
  const start = Math.max(0, Math.min(off, current.length));
  const end = Math.min(current.length, start + len);
  const slice = current.slice(start, end);
  $('formatBox').textContent = detectFormat(current);
  $('entropyBox').textContent = entropyReport(current, slice);
  $('stringsBox').textContent = extractStrings(current, 5).slice(0, 20).join('\n') || '(none)';
  $('hexInfo').textContent = `0x${start.toString(16)} - 0x${end.toString(16)}`;
  $('hexBox').textContent = hexDump(current, start, end);
  $('asmBox').textContent = pseudoDisasm(current, start, end).join('\n');
}

function preferredEntryOffset(b){
  if(b[0]===0x7f && b[1]===0x45 && b[2]===0x4c && b[3]===0x46){
    const is64 = b[4]===2, le = b[5]===1;
    const entry = is64 ? Number(read64(b, 24)) : read32(b, 24);
    const raw = elfVaToOffset(b, entry);
    return '0x' + raw.toString(16);
  }
  if(b[0]===0x4d && b[1]===0x5a) return '0x0';
  return '0x0';
}

function detectFormat(b){
  if(b.length < 4) return 'Raw / unknown';
  if(b[0]===0x7f && b[1]===0x45 && b[2]===0x4c && b[3]===0x46){
    const cls = b[4]===2?'ELF64':b[4]===1?'ELF32':'ELF?';
    const endian = b[5]===1?'little-endian':b[5]===2?'big-endian':'unknown-endian';
    const machine = read16(b,18);
    const entry = b[4]===2 ? read64(b,24) : BigInt(read32(b,24));
    return `${cls} ${endian}\nmachine: ${elfMachine(machine)} (${machine})\nentry/raw VA: 0x${entry.toString(16)}\nphoff: 0x${(b[4]===2?Number(read64(b,32)):read32(b,28)).toString(16)}`;
  }
  if(b[0]===0x4d && b[1]===0x5a){
    const peOff = read32(b,0x3c);
    let pe = (b[peOff]===0x50 && b[peOff+1]===0x45) ? 'PE signature found' : 'MZ header only';
    let machine = pe.includes('PE') ? read16(b, peOff+4) : 0;
    return `Windows executable\n${pe}\nPE offset: 0x${peOff.toString(16)}\nmachine: ${peMachine(machine)} (${machine||'n/a'})`;
  }
  return `Raw / unknown\nmagic: ${[...b.slice(0,4)].map(x=>x.toString(16).padStart(2,'0')).join(' ')}`;
}

function entropyReport(all, slice){
  return `whole file: ${entropy(all).toFixed(3)} / 8\nselected range: ${entropy(slice).toFixed(3)} / 8\ninterpretation: ${entropy(all)>7.2?'packed/encrypted-looking':entropy(all)>6.2?'mixed code/data':'low/normal entropy'}`;
}

function pseudoDisasm(b, start, end){
  const out=[]; let i=start;
  while(i<end){
    const pc=i, x=b[i], y=b[i+1], z=b[i+2]; let text='', n=1;
    const imm8 = () => s8(b[i+1]);
    const imm32 = () => read32(b,i+1);
    const rel32 = () => (i+5+s32(read32(b,i+1)))>>>0;
    if(x===0x90) text='nop';
    else if(x===0xcc) text='int3 ; breakpoint';
    else if(x===0xc3) text='ret';
    else if(x===0xc9) text='leave';
    else if(x===0x55) text='push rbp';
    else if(x===0x53) text='push rbx';
    else if(x===0x57) text='push rdi';
    else if(x===0x56) text='push rsi';
    else if(x===0x5d) text='pop rbp';
    else if(x===0x5b) text='pop rbx';
    else if(x===0x5f) text='pop rdi';
    else if(x===0x5e) text='pop rsi';
    else if(x>=0x50 && x<=0x57) text=`push ${reg64(x-0x50)}`;
    else if(x>=0x58 && x<=0x5f) text=`pop ${reg64(x-0x58)}`;
    else if(x===0x31 && y===0xc0){ text='xor eax,eax'; n=2; }
    else if(x===0x48 && y===0x31 && z===0xc0){ text='xor rax,rax'; n=3; }
    else if(x===0x48 && y===0x89 && z===0xe5){ text='mov rbp,rsp'; n=3; }
    else if(x===0x48 && y===0x83 && z===0xec){ text=`sub rsp, ${hex(b[i+3])}`; n=4; }
    else if(x===0x48 && y===0x83 && z===0xc4){ text=`add rsp, ${hex(b[i+3])}`; n=4; }
    else if(x===0xb8){ text=`mov eax, 0x${imm32().toString(16)}`; n=5; }
    else if(x>=0xb8 && x<=0xbf){ text=`mov ${reg32(x-0xb8)}, 0x${imm32().toString(16)}`; n=5; }
    else if(x===0xe8){ text=`call 0x${rel32().toString(16)}`; n=5; }
    else if(x===0xe9){ text=`jmp 0x${rel32().toString(16)}`; n=5; }
    else if(x===0xeb){ text=`jmp short 0x${((i+2+imm8())>>>0).toString(16)}`; n=2; }
    else if(x===0x74){ text=`jz 0x${((i+2+imm8())>>>0).toString(16)}`; n=2; }
    else if(x===0x75){ text=`jnz 0x${((i+2+imm8())>>>0).toString(16)}`; n=2; }
    else if(x===0x0f && y===0x05){ text='syscall'; n=2; }
    else if(x===0xcd && y===0x80){ text='int 0x80 ; linux i386 syscall'; n=2; }
    else if(x===0x68){ text=`push 0x${imm32().toString(16)}`; n=5; }
    else if(x===0x6a){ text=`push ${hex(b[i+1])}`; n=2; }
    else if(x===0x48 && y===0x8d){ text='lea r?, [rip/stack + disp] ; pseudo'; n=3; }
    else if(x===0x48 && y===0xc7){ text='mov qword/reg, imm32 ; pseudo'; n=Math.min(7,end-i); }
    else if(x===0x89 || x===0x8b || x===0x88 || x===0x8a){ text=`${x===0x8b||x===0x8a?'mov reg,[mem/reg]':'mov [mem/reg],reg'} ; modrm=${hex(y)}`; n=2; }
    else if(x===0x83){ text=`alu r/m, ${hex(z)} ; modrm=${hex(y)}`; n=3; }
    else if(x===0xff){ text=`call/jmp/push r/m ; modrm=${hex(y)}`; n=2; }
    else text=`db ${hex(x)} ; unknown`;
    const bytes=[...b.slice(i, Math.min(i+n,end))].map(v=>v.toString(16).padStart(2,'0')).join(' ');
    out.push(`${pc.toString(16).padStart(8,'0')}:  ${bytes.padEnd(18)} ${text}`);
    i += n;
  }
  return out;
}

function hexDump(b,start,end){
  let s='';
  for(let i=start;i<end;i+=16){
    const row=b.slice(i,Math.min(i+16,end));
    const hx=[...row].map(x=>x.toString(16).padStart(2,'0')).join(' ').padEnd(47);
    const asc=[...row].map(x=>x>=32&&x<127?String.fromCharCode(x):'.').join('');
    s += `${i.toString(16).padStart(8,'0')}  ${hx}  |${asc}|\n`;
  }
  return s;
}

function extractStrings(b,min=5){
  const res=[]; let cur='', off=0;
  for(let i=0;i<b.length;i++){
    const c=b[i];
    if(c>=32 && c<=126){ if(!cur) off=i; cur+=String.fromCharCode(c); }
    else { if(cur.length>=min) res.push(`0x${off.toString(16).padStart(8,'0')}  ${cur.slice(0,120)}`); cur=''; }
  }
  if(cur.length>=min) res.push(`0x${off.toString(16).padStart(8,'0')}  ${cur.slice(0,120)}`);
  return res;
}

function entropy(b){
  if(!b.length) return 0;
  const f=new Array(256).fill(0); for(const x of b) f[x]++;
  let e=0; for(const n of f){ if(n){ const p=n/b.length; e -= p*Math.log2(p); } }
  return e;
}

function elfVaToOffset(b, va){
  if(!(b[0]===0x7f && b[1]===0x45 && b[2]===0x4c && b[3]===0x46)) return va;
  const is64 = b[4]===2, le = b[5]===1;
  if(!le) return 0;
  const phoff = is64 ? Number(read64(b,32)) : read32(b,28);
  const phentsize = read16(b, is64 ? 54 : 42);
  const phnum = read16(b, is64 ? 56 : 44);
  for(let n=0;n<phnum;n++){
    const p = phoff + n*phentsize;
    if(p+phentsize > b.length) break;
    const type = read32(b,p);
    if(type !== 1) continue; // PT_LOAD
    let off, vaddr, filesz, memsz;
    if(is64){
      off = Number(read64(b,p+8));
      vaddr = Number(read64(b,p+16));
      filesz = Number(read64(b,p+32));
      memsz = Number(read64(b,p+40));
    } else {
      off = read32(b,p+4);
      vaddr = read32(b,p+8);
      filesz = read32(b,p+16);
      memsz = read32(b,p+20);
    }
    const span = Math.max(filesz, memsz);
    if(va >= vaddr && va < vaddr + span){
      const raw = off + (va - vaddr);
      return Math.max(0, Math.min(raw, b.length-1));
    }
  }
  return Math.max(0, Math.min(va, b.length-1));
}

function exportReport(){
  const txt = `BinScope PseudoASM report\nfile: ${currentName}\n\n[format]\n${$('formatBox').textContent}\n\n[entropy]\n${$('entropyBox').textContent}\n\n[strings]\n${$('stringsBox').textContent}\n\n[hex]\n${$('hexBox').textContent}\n\n[pseudo-asm]\n${$('asmBox').textContent}`;
  const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([txt],{type:'text/plain'})); a.download=currentName+'.report.txt'; a.click(); URL.revokeObjectURL(a.href);
}
function fmtSize(n){return n<1024?n+' B':n<1048576?(n/1024).toFixed(1)+' KB':(n/1048576).toFixed(1)+' MB'}
function parseNum(s){s=String(s).trim(); return s.startsWith('0x')?parseInt(s,16):parseInt(s,10)||0}
function read16(b,o){return (b[o]||0)|((b[o+1]||0)<<8)}
function read32(b,o){return ((b[o]||0)|((b[o+1]||0)<<8)|((b[o+2]||0)<<16)|((b[o+3]||0)<<24))>>>0}
function read64(b,o){return BigInt(read32(b,o)) | (BigInt(read32(b,o+4))<<32n)}
function s8(x){return x>127?x-256:x}
function s32(x){return x>0x7fffffff?x-0x100000000:x}
function hex(x){return '0x'+(x||0).toString(16).padStart(2,'0')}
function reg64(i){return ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi'][i]||'r?'}
function reg32(i){return ['eax','ecx','edx','ebx','esp','ebp','esi','edi'][i]||'e?'}
function elfMachine(m){return ({3:'x86',62:'x86-64',40:'ARM',183:'AArch64',243:'RISC-V'})[m]||'unknown'}
function peMachine(m){return ({0x14c:'x86',0x8664:'x86-64',0xaa64:'AArch64'})[m]||'unknown'}
