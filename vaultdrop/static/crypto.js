// Chunked AES-256-GCM file encryption (format "VDR1") built on WebCrypto.
//
//   file   := "VDR1" || u32be(headerLength) || header || chunk_0 || ... || chunk_n
//   header := AES-GCM(JSON {v, name, type, size, chunkSize})      nonce(0, 0)
//   chunk  := AES-GCM(plaintext slice of <= chunkSize bytes)      nonce(1, index)
//
// Nonces are counters, not random: the key is generated per file and never reused,
// so a (key, nonce) pair cannot repeat, and re-encrypting the same file with the
// same key reproduces the same bytes, which is what lets an interrupted upload
// resume. Every chunk binds its index and a "final" flag as authenticated data, so
// reordering, dropping, duplicating or truncating chunks fails authentication; the
// header (also authenticated) fixes the plaintext size, so extension is rejected too.

export const DEFAULT_CHUNK_SIZE = 1024 * 1024;
export const TAG_BYTES = 16;
const MAGIC = new Uint8Array([0x56, 0x44, 0x52, 0x31]); // "VDR1"
const MAX_HEADER_BYTES = 64 * 1024;
const MAX_CHUNK_SIZE = 16 * 1024 * 1024;
const KIND_HEADER = 0;
const KIND_CHUNK = 1;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export class FormatError extends Error {
  constructor(message) {
    super(message);
    this.name = "FormatError";
  }
}

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function fromBase64Url(text) {
  if (!/^[A-Za-z0-9_-]+$/.test(text)) throw new FormatError("Malformed key");
  const padded = text.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(text.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

export async function generateKey() {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

export async function exportKey(key) {
  return toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", key)));
}

export async function importKey(text) {
  const raw = fromBase64Url(text);
  if (raw.length !== 32) throw new FormatError("The key in this link is not a 256-bit key");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", true, ["encrypt", "decrypt"]);
}

function nonce(kind, index) {
  const bytes = new Uint8Array(12);
  bytes[0] = kind;
  new DataView(bytes.buffer).setBigUint64(4, BigInt(index));
  return bytes;
}

function aad(kind, index, final) {
  const bytes = new Uint8Array(14);
  bytes.set(encoder.encode("vd"), 0);
  bytes[2] = 1; // format version
  bytes[3] = kind;
  new DataView(bytes.buffer).setBigUint64(4, BigInt(index));
  bytes[12] = final ? 1 : 0;
  return bytes;
}

async function seal(key, kind, index, final, plain) {
  const sealed = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce(kind, index), additionalData: aad(kind, index, final) }, key, plain);
  return new Uint8Array(sealed);
}

async function open(key, kind, index, final, sealed) {
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce(kind, index), additionalData: aad(kind, index, final) }, key, sealed));
  } catch {
    throw new FormatError("Decryption failed: wrong key, or the file was modified");
  }
}

export function chunkCount(size, chunkSize) {
  return Math.max(1, Math.ceil(size / chunkSize));
}

/** Encrypt `blob`; returns the exact output length up front and a lazy chunk generator. */
export async function sealFile(blob, key, { name = "", type = "", chunkSize = DEFAULT_CHUNK_SIZE } = {}) {
  const size = blob.size;
  const header = await seal(key, KIND_HEADER, 0, true,
    encoder.encode(JSON.stringify({ v: 1, name, type, size, chunkSize })));
  if (header.length > MAX_HEADER_BYTES) throw new FormatError("File name is too long");
  const prefix = new Uint8Array(MAGIC.length + 4 + header.length);
  prefix.set(MAGIC, 0);
  new DataView(prefix.buffer).setUint32(MAGIC.length, header.length);
  prefix.set(header, MAGIC.length + 4);
  const count = chunkCount(size, chunkSize);
  return {
    totalLength: prefix.length + size + count * TAG_BYTES,
    async *chunks() {
      yield prefix;
      for (let index = 0; index < count; index++) {
        const plain = await blob.slice(index * chunkSize, Math.min((index + 1) * chunkSize, size)).arrayBuffer();
        yield await seal(key, KIND_CHUNK, index, index === count - 1, plain);
      }
    },
  };
}

class ByteReader {
  constructor(source) {
    this.iterator = source[Symbol.asyncIterator]();
    this.pending = [];
    this.buffered = 0;
  }

  async fill(wanted) {
    while (this.buffered < wanted) {
      const { value, done } = await this.iterator.next();
      if (done) return;
      if (value.length) {
        this.pending.push(value);
        this.buffered += value.length;
      }
    }
  }

  async take(count) {
    await this.fill(count);
    if (this.buffered < count) throw new FormatError("The encrypted file is truncated");
    const out = new Uint8Array(count);
    let filled = 0;
    while (filled < count) {
      const head = this.pending[0];
      const used = Math.min(head.length, count - filled);
      out.set(head.subarray(0, used), filled);
      filled += used;
      if (used === head.length) this.pending.shift();
      else this.pending[0] = head.subarray(used);
    }
    this.buffered -= count;
    return out;
  }

  async expectEnd() {
    await this.fill(1);
    if (this.buffered > 0) throw new FormatError("The encrypted file has unexpected trailing data");
  }
}

/** Adapt a fetch Response body (or any async iterable of Uint8Array) for `openFile`. */
export function iterate(body) {
  if (body[Symbol.asyncIterator]) return body;
  return (async function* () {
    const reader = body.getReader();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) return;
        yield value;
      }
    } finally {
      reader.releaseLock();
    }
  })();
}

function validateHeader(header) {
  const sane = header && header.v === 1
    && Number.isSafeInteger(header.size) && header.size >= 0
    && Number.isSafeInteger(header.chunkSize) && header.chunkSize > 0 && header.chunkSize <= MAX_CHUNK_SIZE
    && typeof header.name === "string" && typeof header.type === "string";
  if (!sane) throw new FormatError("Unsupported or corrupt file header");
}

/** Authenticate the header, then return it with a generator that yields verified plaintext. */
export async function openFile(source, key) {
  const reader = new ByteReader(source);
  const magic = await reader.take(MAGIC.length);
  if (!MAGIC.every((byte, i) => byte === magic[i])) throw new FormatError("Not a VaultDrop file");
  const headerLength = new DataView((await reader.take(4)).buffer).getUint32(0);
  if (headerLength < TAG_BYTES || headerLength > MAX_HEADER_BYTES) throw new FormatError("Corrupt file header");
  const opened = await open(key, KIND_HEADER, 0, true, await reader.take(headerLength));
  let header;
  try {
    header = JSON.parse(decoder.decode(opened));
  } catch {
    throw new FormatError("Corrupt file header");
  }
  validateHeader(header);
  const count = chunkCount(header.size, header.chunkSize);
  return {
    header,
    async *plaintext() {
      for (let index = 0; index < count; index++) {
        const last = index === count - 1;
        const plainLength = last ? header.size - index * header.chunkSize : header.chunkSize;
        yield await open(key, KIND_CHUNK, index, last, await reader.take(plainLength + TAG_BYTES));
      }
      await reader.expectEnd();
    },
  };
}
