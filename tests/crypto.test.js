import test from "node:test";
import assert from "node:assert/strict";
const { encryptChunk, decryptChunk } = await import("../static/crypto.js");

async function key() {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

test("decrypts a correctly sealed chunk", async () => {
  const k = await key();
  const sealed = await encryptChunk(new TextEncoder().encode("secret"), k, 0, true);
  const plain = await decryptChunk(sealed, k, 0, true);
  assert.equal(new TextDecoder().decode(plain), "secret");
});

test("tampering fails authentication", async () => {
  const k = await key();
  const sealed = await encryptChunk(new Uint8Array(32), k, 0, false);
  sealed[20] ^= 1;
  await assert.rejects(() => decryptChunk(sealed, k, 0, false));
});

test("reordering chunks fails the chunk-index AAD", async () => {
  const k = await key();
  const first = await encryptChunk(new Uint8Array(32), k, 0, false);
  await assert.rejects(() => decryptChunk(first, k, 1, false));
});

test("truncation fails", async () => {
  const k = await key();
  await assert.rejects(() => decryptChunk(new Uint8Array(12), k, 0, true));
});
