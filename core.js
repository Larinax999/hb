// core.js — shared parsing/search logic. No DOM, no fetch; works in Node and browsers.

export const MAGIC_ACCOUNTS = "BCHK";
export const MAGIC_PW = "BPWI";
export const VERSION = 1;

// magic(4) | version u8 | reserved(3) | entryCount u32 LE — total 12 bytes
const HEADER_SIZE = 12;

function asBytes(buf) {
  return buf instanceof Uint8Array ? buf : new Uint8Array(buf);
}

function checkHeader(buf, magic, label) {
  if (buf.length < HEADER_SIZE) throw new Error(`invalid ${label} data`);
  for (let i = 0; i < 4; i++) {
    if (buf[i] !== magic.charCodeAt(i)) throw new Error(`invalid ${label} data`);
  }
  if (buf[4] !== VERSION) throw new Error(`invalid ${label} data`);
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  return dv.getUint32(8, true);
}

// parseAccounts: buf = Uint8Array (or ArrayBuffer) over the whole file
export function parseAccounts(buf) {
  buf = asBytes(buf);
  const count = checkHeader(buf, MAGIC_ACCOUNTS, "accounts");
  // entries region starts at HEADER_SIZE; offsets index is the last count*4 bytes
  const idxStart = buf.length - count * 4;
  const entriesEnd = idxStart;
  if (idxStart < HEADER_SIZE) throw new Error("invalid accounts data");
  const nameOffsets = new Uint32Array(count + 1);
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  for (let i = 0; i < count; i++) {
    nameOffsets[i] = dv.getUint32(idxStart + i * 4, true);
  }
  nameOffsets[count] = entriesEnd;
  // sanity: offsets within entries region
  for (let i = 0; i < count; i++) {
    if (nameOffsets[i] < HEADER_SIZE || nameOffsets[i] >= entriesEnd) throw new Error("invalid accounts data");
  }
  return { entryCount: count, nameOffsets, entriesEnd, buf };
}

export function parsePwIndex(accounts, buf) {
  buf = asBytes(buf);
  const count = checkHeader(buf, MAGIC_PW, "pw-index");
  if (count !== accounts.entryCount) throw new Error("invalid pw-index data");
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const offsets = new Uint32Array(count);
  if (HEADER_SIZE + count * 4 > buf.length) throw new Error("invalid pw-index data");
  for (let i = 0; i < count; i++) {
    const off = dv.getUint32(HEADER_SIZE + i * 4, true);
    if (off < HEADER_SIZE || off >= accounts.entriesEnd) throw new Error("invalid pw-index data");
    offsets[i] = off;
  }
  return { offsets };
}

export function readEntry(accounts, i) {
  return readEntryAt(accounts, accounts.nameOffsets[i]);
}

// Reads the entry starting at byte offset `off` in the entries region.
// (pw-index stores byte offsets, not entry indices.)
function readEntryAt(accounts, off) {
  const { buf } = accounts;
  const nameLen = buf[off] | (buf[off + 1] << 8);
  const nameBytes = buf.subarray(off + 2, off + 2 + nameLen);
  const hashBytes = buf.subarray(off + 2 + nameLen, off + 2 + nameLen + 32);
  return { nameBytes, hashBytes };
}

function compareBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = a[i] - b[i];
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

// Returns index of first entry with username >= nameBytes (lower bound)
function usernameLowerBound(accounts, nameBytes) {
  let lo = 0, hi = accounts.entryCount;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (compareBytes(readEntry(accounts, mid).nameBytes, nameBytes) < 0) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

export function searchUsername(accounts, nameBytes) {
  const hits = [];
  for (let i = usernameLowerBound(accounts, nameBytes); i < accounts.entryCount; i++) {
    const e = readEntry(accounts, i);
    if (compareBytes(e.nameBytes, nameBytes) !== 0) break;
    hits.push(e);
  }
  return hits;
}

export function searchHash(accounts, pwIndex, hashBytes) {
  const { offsets } = pwIndex;
  let lo = 0, hi = offsets.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    const entryHash = readEntryAt(accounts, offsets[mid]).hashBytes;
    if (compareBytes(entryHash, hashBytes) < 0) lo = mid + 1;
    else hi = mid;
  }
  if (lo < offsets.length) {
    const e = readEntryAt(accounts, offsets[lo]);
    if (compareBytes(e.hashBytes, hashBytes) === 0) return true;
  }
  return false;
}

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
export function toHex(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += HEX[bytes[i]];
  return s;
}
