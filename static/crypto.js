export function chunkAad(chunkIndex, finalFlag) {
  return new TextEncoder().encode(JSON.stringify({
    project: "vaultdrop",
    chunkIndex,
    final: finalFlag ? 1 : 0,
  }));
}

export async function encryptChunk(plain, key, chunkIndex, finalFlag) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: chunkAad(chunkIndex, finalFlag) },
    key,
    plain,
  ));
  const envelope = new Uint8Array(12 + ciphertext.byteLength);
  envelope.set(nonce, 0);
  envelope.set(ciphertext, 12);
  return envelope;
}

export async function decryptChunk(envelope, key, chunkIndex, finalFlag) {
  if (envelope.byteLength < 28) throw new Error("Truncated encrypted chunk");
  const nonce = envelope.slice(0, 12);
  const ciphertext = envelope.slice(12);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce, additionalData: chunkAad(chunkIndex, finalFlag) },
    key,
    ciphertext,
  );
  return new Uint8Array(plain);
}
