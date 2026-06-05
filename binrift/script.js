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
    const pc=i;
    const d = decodeX86_64(b, i, end);
    const n = Math.max(1, Math.min(d.len, end-i));
    const bytes=[...b.slice(i, Math.min(i+n,end))].map(v=>v.toString(16).padStart(2,'0')).join(' ');
    out.push(`${pc.toString(16).padStart(8,'0')}:  ${bytes.padEnd(22)} ${d.text}`);
    i += n;
  }
  return out;
}

function decodeX86_64(b, i, end){
  let p=i, rex=0, op;
  if(p<end && b[p]>=0x40 && b[p]<=0x4f){ rex=b[p++]; }
  if(p>=end) return {len:1,text:`db ${hex(b[i])} ; unknown`};
  op=b[p++];
  const W=!!(rex&8), R=!!(rex&4), X=!!(rex&2), B=!!(rex&1);
  const bits = W ? 64 : 32;
  const imm8 = () => s8(b[p]);
  const rel8 = () => (i + (p-i) + 1 + s8(b[p])) >>> 0;
  const rel32 = () => (p + 4 + s32(read32(b,p))) >>> 0;
  const need = n => p+n<=end;

  // one byte common instructions
  if(op===0x90) return {len:p-i,text:'nop'};
  if(op===0xcc) return {len:p-i,text:'int3 ; breakpoint'};
  if(op===0xc3) return {len:p-i,text:'ret'};
  if(op===0xc9) return {len:p-i,text:'leave'};
  if(op>=0x50 && op<=0x57) return {len:p-i,text:`push ${reg(64,(op-0x50)+(B?8:0))}`};
  if(op>=0x58 && op<=0x5f) return {len:p-i,text:`pop ${reg(64,(op-0x58)+(B?8:0))}`};
  if(op>=0xb8 && op<=0xbf){
    const r=(op-0xb8)+(B?8:0);
    if(W && need(4)){ const v=read32(b,p); p+=4; return {len:p-i,text:`mov ${reg(64,r)}, 0x${v.toString(16)}`}; }
    if(need(4)){ const v=read32(b,p); p+=4; return {len:p-i,text:`mov ${reg(32,r)}, 0x${v.toString(16)}`}; }
  }
  if(op===0x68 && need(4)){ const v=read32(b,p); p+=4; return {len:p-i,text:`push 0x${v.toString(16)}`}; }
  if(op===0x6a && need(1)){ const v=b[p++]; return {len:p-i,text:`push ${hex(v)}`}; }
  if(op===0xe8 && need(4)){ const t=rel32(); p+=4; return {len:p-i,text:`call 0x${t.toString(16)}`}; }
  if(op===0xe9 && need(4)){ const t=rel32(); p+=4; return {len:p-i,text:`jmp 0x${t.toString(16)}`}; }
  if(op===0xeb && need(1)){ const t=rel8(); p++; return {len:p-i,text:`jmp short 0x${t.toString(16)}`}; }
  if((op===0x74 || op===0x75 || op===0x7c || op===0x7d || op===0x7e || op===0x7f) && need(1)){
    const m={0x74:'jz',0x75:'jnz',0x7c:'jl',0x7d:'jge',0x7e:'jle',0x7f:'jg'}[op]; const t=rel8(); p++; return {len:p-i,text:`${m} 0x${t.toString(16)}`};
  }
  if(op===0xcd && b[p]===0x80){ p++; return {len:p-i,text:'int 0x80 ; linux i386 syscall'}; }
  if(op===0x0f){
    const op2=b[p++];
    if(op2===0x05) return {len:p-i,text:'syscall'};
    const jcc={0x84:'jz',0x85:'jnz',0x8c:'jl',0x8d:'jge',0x8e:'jle',0x8f:'jg'}[op2];
    if(jcc && need(4)){ const t=rel32(); p+=4; return {len:p-i,text:`${jcc} 0x${t.toString(16)}`}; }
    return {len:p-i,text:`db 0x0f, ${hex(op2)} ; unknown`};
  }

  // ModRM-based instructions
  const modrmOps = [0x01,0x03,0x09,0x0b,0x21,0x23,0x29,0x2b,0x31,0x33,0x39,0x3b,0x83,0x85,0x87,0x89,0x8b,0x8d,0xc7,0xff];
  if(modrmOps.includes(op) && p<end){
    const m = parseModRM(b,p,rex,bits); p = m.next;
    const r = reg(bits, m.reg);
    const rm = m.rm;
    const alu = {0:'add',1:'or',4:'and',5:'sub',6:'xor',7:'cmp'};
    if(op===0x89) return {len:p-i,text:`mov ${rm}, ${r}`};
    if(op===0x8b) return {len:p-i,text:`mov ${r}, ${rm}`};
    if(op===0x8d) return {len:p-i,text:`lea ${r}, ${rm.replace(/^qword ptr /,'').replace(/^dword ptr /,'')}`};
    if(op===0x31) return {len:p-i,text:`xor ${rm}, ${r}`};
    if(op===0x33) return {len:p-i,text:`xor ${r}, ${rm}`};
    if(op===0x29) return {len:p-i,text:`sub ${rm}, ${r}`};
    if(op===0x2b) return {len:p-i,text:`sub ${r}, ${rm}`};
    if(op===0x01) return {len:p-i,text:`add ${rm}, ${r}`};
    if(op===0x03) return {len:p-i,text:`add ${r}, ${rm}`};
    if(op===0x39) return {len:p-i,text:`cmp ${rm}, ${r}`};
    if(op===0x3b) return {len:p-i,text:`cmp ${r}, ${rm}`};
    if(op===0x85) return {len:p-i,text:`test ${rm}, ${r}`};
    if(op===0x87) return {len:p-i,text:`xchg ${rm}, ${r}`};
    if(op===0x83 && p<end){ const sub=(m.raw>>3)&7, v=s8(b[p++]); return {len:p-i,text:`${alu[sub]||'alu'} ${rm}, ${v<0?'-0x'+(-v).toString(16):'0x'+v.toString(16)}`}; }
    if(op===0xc7 && p+4<=end){ const v=read32(b,p); p+=4; return {len:p-i,text:`mov ${rm}, 0x${v.toString(16)}`}; }
    if(op===0xff){ const sub=(m.raw>>3)&7; const names={2:'call',4:'jmp',6:'push'}; return {len:p-i,text:`${names[sub]||'ff'} ${rm}`}; }
  }

  return {len:1,text:`db ${hex(b[i])} ; unknown`};
}

function parseModRM(b,p,rex,bits){
  const raw=b[p++], mod=raw>>6, regId=((raw>>3)&7)+((rex&4)?8:0), rmBase=(raw&7)+((rex&1)?8:0);
  let rm='', next=p;
  if(mod===3) return {raw,reg:regId,rm:reg(bits,rmBase),next};
  const ptr=bits===64?'qword ptr':'dword ptr';
  let base='', index='', scale=1, disp=0, hasDisp=false, rip=false;
  let rmLow=raw&7;
  if(rmLow===4){
    const sib=b[next++]; scale=1<<(sib>>6);
    const idx=((sib>>3)&7)+((rex&2)?8:0);
    const bas=(sib&7)+((rex&1)?8:0);
    if(((sib>>3)&7)!==4) index=reg(64,idx);
    if((sib&7)===5 && mod===0){ hasDisp=true; disp=s32(read32(b,next)); next+=4; }
    else base=reg(64,bas);
  } else if(rmLow===5 && mod===0){ rip=true; hasDisp=true; disp=s32(read32(b,next)); next+=4; }
  else base=reg(64,rmBase);
  if(mod===1){ hasDisp=true; disp=s8(b[next++]); }
  if(mod===2){ hasDisp=true; disp=s32(read32(b,next)); next+=4; }
  let expr='';
  if(rip) expr='rip'; else expr=base;
  if(index) expr += `${expr?'+':''}${index}${scale!==1?'*'+scale:''}`;
  if(hasDisp && disp!==0) expr += `${disp<0?'-':'+'}0x${Math.abs(disp).toString(16)}`;
  if(!expr) expr=`0x${(disp>>>0).toString(16)}`;
  rm=`${ptr} [${expr}]`;
  return {raw,reg:regId,rm,next};
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
function reg(bits,i){ return bits===64 ? reg64(i) : reg32(i); }
function reg64(i){return ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15'][i]||'r?'}
function reg32(i){return ['eax','ecx','edx','ebx','esp','ebp','esi','edi','r8d','r9d','r10d','r11d','r12d','r13d','r14d','r15d'][i]||'e?'}
function elfMachine(m){return ({3:'x86',62:'x86-64',40:'ARM',183:'AArch64',243:'RISC-V'})[m]||'unknown'}
function peMachine(m){return ({0x14c:'x86',0x8664:'x86-64',0xaa64:'AArch64'})[m]||'unknown'}
