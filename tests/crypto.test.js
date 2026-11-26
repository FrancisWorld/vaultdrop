import test from "node:test";
import assert from "node:assert/strict";
import {
  FormatError, TAG_BYTES, chunkCount, exportKey, generateKey, importKey, iterate, openFile, sealFile,
} from "../vaultdrop/static/crypto.js";

const CHUNK = 64;

function bytes(length, seed = 1) {
  return Uint8Array.from({ length }, (_, i) => (i * 31 + seed) & 0xff);
}

async function collect(iterable) {
  const out = [];
  for await (const chunk of iterable) out.push(chunk);
  return out;
}

function join(chunks) {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let offset = 0;
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.length; }
  return out;
}

async function seal(plain, key, name = "note.txt") {
  const sealed = await sealFile(new Blob([plain]), key, { name, type: "text/plain", chunkSize: CHUNK });
  return { sealed, chunks: await collect(sealed.chunks()) };
}

async function* feed(buffer, step) {
  for (let i = 0; i < buffer.length; i += step) yield buffer.subarray(i, i + step);
}

async function decrypt(buffer, key, step = 7) {
  const { header, plaintext } = await openFile(feed(buffer, step), key);
  return { header, data: join(await collect(plaintext())) };
}

for (const size of [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, CHUNK * 5, CHUNK * 5 + 3]) {
  test(`round trip of ${size} bytes, delivered in arbitrary slices`, async () => {
    const key = await generateKey();
    const plain = bytes(size);
    const { sealed, chunks } = await seal(plain, key);
    const wire = join(chunks);
    assert.equal(wire.length, sealed.totalLength, "announced length is exact");
    for (const step of [1, 7, CHUNK, 10_000]) {
      const { header, data } = await decrypt(wire, key, step);
      assert.deepEqual(data, plain);
      assert.equal(header.name, "note.txt");
      assert.equal(header.size, size);
    }
  });
}

test("encryption is deterministic for one key, so interrupted uploads can resume", async () => {
  const key = await generateKey();
  const plain = bytes(500);
  const first = join((await seal(plain, key)).chunks);
  const second = join((await seal(plain, key)).chunks);
  assert.deepEqual(first, second);
  const other = join((await seal(plain, await generateKey())).chunks);
  assert.notDeepEqual(first, other);
});

test("ciphertext does not contain the plaintext or the file name", async () => {
  const key = await generateKey();
  const plain = new TextEncoder().encode("a very recognisable plaintext marker");
  const wire = join((await seal(plain, key, "quarterly-notes.pdf")).chunks);
  const text = Buffer.from(wire).toString("latin1");
  assert.ok(!text.includes("recognisable") && !text.includes("quarterly-notes"));
});

test("wrong key fails authentication", async () => {
  const wire = join((await seal(bytes(100), await generateKey())).chunks);
  await assert.rejects(async () => decrypt(wire, await generateKey()), FormatError);
});

test("flipping any single byte is detected", async () => {
  const key = await generateKey();
  const wire = join((await seal(bytes(150), key)).chunks);
  for (let i = 0; i < wire.length; i += 5) {
    const tampered = wire.slice();
    tampered[i] ^= 0x01;
    await assert.rejects(() => decrypt(tampered, key), FormatError, `byte ${i}`);
  }
});

test("reordering chunks is detected", async () => {
  const key = await generateKey();
  const { chunks } = await seal(bytes(CHUNK * 3), key);
  const [prefix, a, b, c] = chunks;
  await assert.rejects(() => decrypt(join([prefix, b, a, c]), key), FormatError);
});

test("dropping the final chunk (truncation) is detected", async () => {
  const key = await generateKey();
  const { chunks } = await seal(bytes(CHUNK * 3), key);
  await assert.rejects(() => decrypt(join(chunks.slice(0, -1)), key), FormatError);
  await assert.rejects(() => decrypt(join(chunks).subarray(0, 10), key), FormatError);
});

test("cutting a chunk mid-way is detected", async () => {
  const key = await generateKey();
  const wire = join((await seal(bytes(200), key)).chunks);
  await assert.rejects(() => decrypt(wire.subarray(0, wire.length - 3), key), FormatError);
});

test("duplicating a chunk or appending data is detected", async () => {
  const key = await generateKey();
  const { chunks } = await seal(bytes(CHUNK * 2), key);
  await assert.rejects(() => decrypt(join([...chunks, chunks[2]]), key), FormatError);
  await assert.rejects(() => decrypt(join([...chunks, new Uint8Array(3)]), key), FormatError);
});

test("not a VaultDrop file, corrupt header length and bad header JSON", async () => {
  const key = await generateKey();
  await assert.rejects(() => decrypt(bytes(64), key), /Not a VaultDrop file/);
  const wire = join((await seal(bytes(10), key)).chunks);
  const huge = wire.slice();
  new DataView(huge.buffer).setUint32(4, 0xffffffff);
  await assert.rejects(() => decrypt(huge, key), /Corrupt file header/);
  await assert.rejects(() => decrypt(new Uint8Array(0), key), /truncated/);
});

test("key export/import round trip and validation", async () => {
  const key = await generateKey();
  const text = await exportKey(key);
  assert.match(text, /^[A-Za-z0-9_-]{43}$/);
  const imported = await importKey(text);
  const wire = join((await seal(bytes(30), key)).chunks);
  assert.deepEqual((await decrypt(wire, imported)).data, bytes(30));
  await assert.rejects(() => importKey("not base64!"), FormatError);
  await assert.rejects(() => importKey("AAAA"), FormatError);
});

test("chunkCount always has at least one (possibly empty) final chunk", () => {
  assert.equal(chunkCount(0, 10), 1);
  assert.equal(chunkCount(10, 10), 1);
  assert.equal(chunkCount(11, 10), 2);
  assert.equal(TAG_BYTES, 16);
});

test("iterate adapts a ReadableStream", async () => {
  const stream = new ReadableStream({ start(c) { c.enqueue(new Uint8Array([1, 2])); c.enqueue(new Uint8Array([3])); c.close(); } });
  const reader = { getReader: () => stream.getReader() };
  assert.deepEqual(join(await collect(iterate(reader))), new Uint8Array([1, 2, 3]));
});
