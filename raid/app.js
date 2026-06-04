let disks = [];
let logLines = [];
let lastPayload = "";

const $ = (id) => document.getElementById(id);

const RAID_INFO = {
  "0": ["RAID 0", "Data is striped across disks for speed. Any disk failure destroys the array."],
  "1": ["RAID 1", "Every disk stores a complete mirror copy. Capacity equals one disk, but redundancy is high."],
  "5": ["RAID 5", "Data and XOR parity are distributed across disks. One failed disk can be rebuilt."],
  "6": ["RAID 6", "Data plus two parity blocks are distributed. This simulator models P and Q recovery behavior at a training level."],
  "10": ["RAID 10", "Mirrored pairs are striped. It survives one failure per mirror pair."],
  "01": ["RAID 01", "Striped sets are mirrored. After one disk fails, the opposite stripe set carries the array."],
  "jbod": ["JBOD", "Disks are concatenated. Data fills one disk then continues to the next. No redundancy."],
};

function minDisks(mode) {
  return {"0":2,"1":2,"5":3,"6":4,"10":4,"01":4,"jbod":2}[mode] || 2;
}

function normalizeDiskCount(mode, count) {
  count = Math.max(minDisks(mode), Math.min(12, count));
  if ((mode === "10" || mode === "01") && count % 2 !== 0) count += 1;
  return Math.min(12, count);
}

function log(msg) {
  const t = new Date().toLocaleTimeString();
  logLines.unshift(`[${t}] ${msg}`);
  logLines = logLines.slice(0, 80);
  $("eventLog").textContent = logLines.join("\n");
}

function initRaid() {
  const mode = $("raidMode").value;
  const count = normalizeDiskCount(mode, Number($("diskCount").value));
  $("diskCount").value = count;
  disks = Array.from({length: count}, (_, i) => ({ id: i, failed: false, blocks: [] }));
  log(`Initialized ${RAID_INFO[mode][0]} with ${count} disks`);
  render();
}

function makeBlocks(data) {
  return (data.match(/.{1,2}/g) || []).map((value, i) => ({ label: `B${i}`, value }));
}

function blockNum(b) {
  return [...b.value].reduce((n, c) => n ^ c.charCodeAt(0), 0);
}

function parityValue(blocks, prefix = "P") {
  const n = blocks.reduce((acc, b) => acc ^ blockNum(b), 0);
  return `${prefix}${n.toString(16).padStart(2, "0")}`;
}

function pushBlock(diskIndex, type, value, source = "") {
  disks[diskIndex].blocks.push({ type, value, source });
}

function writeData() {
  if (!disks.length) initRaid();
  disks.forEach(d => d.blocks = []);
  const mode = $("raidMode").value;
  lastPayload = $("dataInput").value;
  const blocks = makeBlocks(lastPayload);

  if (mode === "0") writeRaid0(blocks);
  if (mode === "1") writeRaid1(blocks);
  if (mode === "5") writeRaid5(blocks);
  if (mode === "6") writeRaid6(blocks);
  if (mode === "10") writeRaid10(blocks);
  if (mode === "01") writeRaid01(blocks);
  if (mode === "jbod") writeJbod(blocks);

  log(`Wrote ${blocks.length} data blocks to ${RAID_INFO[mode][0]}`);
  render();
}

function writeRaid0(blocks) {
  blocks.forEach((b, i) => pushBlock(i % disks.length, "data", b.value, b.label));
}

function writeRaid1(blocks) {
  disks.forEach(d => blocks.forEach(b => pushBlock(d.id, "mirror", b.value, b.label)));
}

function writeRaid5(blocks) {
  const dataDisks = disks.length - 1;
  for (let i = 0, stripe = 0; i < blocks.length; i += dataDisks, stripe++) {
    const chunk = blocks.slice(i, i + dataDisks);
    while (chunk.length < dataDisks) chunk.push({ label: "PAD", value: "00" });
    const pDisk = stripe % disks.length;
    let c = 0;
    disks.forEach((_, d) => {
      if (d === pDisk) pushBlock(d, "parity", parityValue(chunk, "P"), `S${stripe}`);
      else pushBlock(d, "data", chunk[c].value, chunk[c++].label);
    });
  }
}

function writeRaid6(blocks) {
  const dataDisks = disks.length - 2;
  for (let i = 0, stripe = 0; i < blocks.length; i += dataDisks, stripe++) {
    const chunk = blocks.slice(i, i + dataDisks);
    while (chunk.length < dataDisks) chunk.push({ label: "PAD", value: "00" });
    const pDisk = stripe % disks.length;
    const qDisk = (stripe + 1) % disks.length;
    let c = 0;
    disks.forEach((_, d) => {
      if (d === pDisk) pushBlock(d, "parity", parityValue(chunk, "P"), `S${stripe}`);
      else if (d === qDisk) pushBlock(d, "parity2", parityValue(chunk.map((b, idx) => ({value: String.fromCharCode(blockNum(b) ^ (idx + 17))})), "Q"), `S${stripe}`);
      else pushBlock(d, "data", chunk[c].value, chunk[c++].label);
    });
  }
}

function writeRaid10(blocks) {
  const pairs = disks.length / 2;
  blocks.forEach((b, i) => {
    const pair = i % pairs;
    pushBlock(pair * 2, "data", b.value, b.label);
    pushBlock(pair * 2 + 1, "mirror", b.value, b.label);
  });
}

function writeRaid01(blocks) {
  const half = disks.length / 2;
  blocks.forEach((b, i) => {
    const diskA = i % half;
    const diskB = diskA + half;
    pushBlock(diskA, "data", b.value, b.label);
    pushBlock(diskB, "mirror", b.value, b.label);
  });
}

function writeJbod(blocks) {
  const perDisk = Math.ceil(blocks.length / disks.length);
  blocks.forEach((b, i) => pushBlock(Math.floor(i / perDisk), "data", b.value, b.label));
}

function failDisk(id) {
  disks[id].failed = true;
  log(`Disk ${id} marked FAILED`);
  render();
}

function repairDisk(id) {
  disks[id].failed = false;
  log(`Disk ${id} manually returned online`);
  render();
}

function randomFail() {
  const candidates = disks.filter(d => !d.failed);
  if (!candidates.length) return;
  failDisk(candidates[Math.floor(Math.random() * candidates.length)].id);
}

function rebuild() {
  const failed = disks.filter(d => d.failed).map(d => d.id);
  if (!failed.length) return log("No failed disk to rebuild");
  const mode = $("raidMode").value;
  const status = healthStatus();
  if (!status.rebuildable) return log(`Rebuild failed: ${status.reason}`);

  const snapshot = JSON.parse(JSON.stringify(disks));
  failed.forEach(id => disks[id].blocks = []);

  if (["1", "5", "6", "10", "01"].includes(mode)) {
    writeData();
    failed.forEach(id => {
      disks[id].failed = false;
      disks[id].blocks = disks[id].blocks.map(b => ({...b, type: b.type === "parity" || b.type === "parity2" ? b.type : "rebuilt"}));
    });
    log(`Rebuilt disk(s): ${failed.join(", ")}`);
  } else {
    disks = snapshot;
    log(`${RAID_INFO[mode][0]} has no redundancy; rebuild cannot recover data`);
  }
  render();
}

function failedIds() { return disks.filter(d => d.failed).map(d => d.id); }

function healthStatus() {
  const mode = $("raidMode").value;
  const f = failedIds();
  const n = f.length;
  if (n === 0) return { state: "ok", title: "Healthy", text: "No failed disks", rebuildable: false, reason: "No failure" };

  if (mode === "0" || mode === "jbod") return { state: "bad", title: "Data Lost", text: `${n} failed disk(s)`, rebuildable: false, reason: "No redundancy" };
  if (mode === "1") return n < disks.length ? { state: "warn", title: "Degraded", text: `${n} mirror disk(s) failed`, rebuildable: true } : { state: "bad", title: "Data Lost", text: "All mirrors failed", rebuildable: false, reason: "All copies failed" };
  if (mode === "5") return n <= 1 ? { state: "warn", title: "Degraded", text: "Single disk failure tolerated", rebuildable: true } : { state: "bad", title: "Data Lost", text: "RAID 5 tolerates only one failure", rebuildable: false, reason: "Too many failures" };
  if (mode === "6") return n <= 2 ? { state: "warn", title: "Degraded", text: "Dual disk failure tolerated", rebuildable: true } : { state: "bad", title: "Data Lost", text: "RAID 6 tolerates two failures", rebuildable: false, reason: "Too many failures" };
  if (mode === "10") {
    for (let i = 0; i < disks.length; i += 2) if (disks[i].failed && disks[i+1].failed) return { state: "bad", title: "Data Lost", text: `Mirror pair ${i/2} lost`, rebuildable: false, reason: "A mirror pair is gone" };
    return { state: "warn", title: "Degraded", text: `${n} failed disk(s), mirror pairs still alive`, rebuildable: true };
  }
  if (mode === "01") {
    const half = disks.length / 2;
    const leftDead = f.some(id => id < half);
    const rightDead = f.some(id => id >= half);
    return leftDead && rightDead ? { state: "bad", title: "Data Lost", text: "Both stripe sets damaged", rebuildable: false, reason: "Both mirrored stripe sets failed" } : { state: "warn", title: "Degraded", text: "One stripe set damaged", rebuildable: true };
  }
}

function usableCapacity() {
  const mode = $("raidMode").value;
  const size = Number($("diskSize").value);
  const n = disks.length || normalizeDiskCount(mode, Number($("diskCount").value));
  if (mode === "0" || mode === "jbod") return n * size;
  if (mode === "1") return size;
  if (mode === "5") return (n - 1) * size;
  if (mode === "6") return (n - 2) * size;
  if (mode === "10" || mode === "01") return (n / 2) * size;
  return 0;
}

function failureToleranceText() {
  const mode = $("raidMode").value;
  if (mode === "0" || mode === "jbod") return "0 disks";
  if (mode === "1") return `${Math.max(0, disks.length - 1)} disks`;
  if (mode === "5") return "1 disk";
  if (mode === "6") return "2 disks";
  if (mode === "10") return "1 per mirror pair";
  if (mode === "01") return "usually 1 stripe set";
}

function render() {
  const mode = $("raidMode").value;
  $("modeTitle").textContent = RAID_INFO[mode][0];
  $("modeDesc").textContent = RAID_INFO[mode][1];

  const health = healthStatus();
  $("healthTitle").textContent = health.title;
  $("healthText").textContent = health.text;
  const dot = document.querySelector(".dot");
  dot.className = `dot ${health.state === "ok" ? "ok" : health.state === "warn" ? "warn" : "bad"}`;

  const total = (disks.length || Number($("diskCount").value)) * Number($("diskSize").value);
  $("stats").innerHTML = `
    <div class="stat"><small>Total Raw</small><strong>${total} GB</strong></div>
    <div class="stat"><small>Usable</small><strong>${usableCapacity()} GB</strong></div>
    <div class="stat"><small>Failure Tolerance</small><strong>${failureToleranceText()}</strong></div>
    <div class="stat"><small>Failed</small><strong>${failedIds().length}</strong></div>
  `;

  $("disks").innerHTML = disks.map(d => `
    <article class="disk ${d.failed ? "failed" : ""}">
      <div class="disk-head">
        <div>
          <h3>Disk ${d.id}</h3>
          <div class="disk-meta">${d.blocks.length} block(s)</div>
        </div>
      </div>
      <div class="blocks">
        ${d.blocks.map(b => `<div class="block ${b.type}" title="${b.source}">${b.source ? b.source + ":" : ""}${b.value}</div>`).join("") || `<div class="disk-meta">empty</div>`}
      </div>
      <div class="disk-actions">
        <button class="danger" onclick="failDisk(${d.id})">Fail</button>
        <button onclick="repairDisk(${d.id})">Online</button>
      </div>
    </article>
  `).join("");
}

$("initBtn").onclick = initRaid;
$("writeBtn").onclick = writeData;
$("rebuildBtn").onclick = rebuild;
$("randomFailBtn").onclick = randomFail;
$("clearLogBtn").onclick = () => { logLines = []; $("eventLog").textContent = ""; };
$("raidMode").onchange = initRaid;
$("diskCount").onchange = initRaid;
$("diskSize").onchange = render;

initRaid();
writeData();
