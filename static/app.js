import { decryptChunk, encryptChunk } from "./crypto.js";

const fileInput = document.querySelector("#file");
const fileName = document.querySelector("#fileName");
const status = document.querySelector("#status");
const progress = document.querySelector("#progress");
const bar = document.querySelector("#bar");

fileInput.addEventListener("change", () => {
  fileName.textContent = fileInput.files[0]?.name || "Choose or drop a file";
});

async function sha256(buffer) {
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function upload() {
  const file = fileInput.files[0];
  if (!file) { status.textContent = "Choose a file first."; return; }
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  status.textContent = "Encrypting in your browser...";
  const plainSize = file.size;
  const plainPartSize = 8 * 1024 * 1024 - 28;
  const partCount = plainSize ? Math.ceil(plainSize / plainPartSize) : 1;
  const ciphertextParts = [];
  for (let i = 0; i < partCount; i++) {
    const start = i * plainPartSize;
    const end = Math.min(start + plainPartSize, plainSize);
    const plain = await file.slice(start, end).arrayBuffer();
    ciphertextParts.push(await encryptChunk(plain, key, i, i === partCount - 1));
  }
  const cipherText = new Blob(ciphertextParts, { type: "application/octet-stream" });
  const checksum = await sha256(await cipherText.arrayBuffer());
  const partSize = 8 * 1024 * 1024;
  progress.hidden = false;

  const initiated = await fetch("/v1/uploads", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ filename: `${file.name}.encrypted`, size_bytes: cipherText.size, sha256: checksum, part_size: partSize }),
  }).then((r) => r.json());
  if (!initiated.upload_id) throw new Error(initiated.detail || "Upload initiation failed");

  const completeParts = [];
  const parts = ciphertextParts.length;
  for (let i = 0; i < parts; i++) {
    const chunk = ciphertextParts[i];
    const url = initiated.urls[i].url;
    const response = await fetch(url, { method: "PUT", body: chunk });
    const etag = response.headers.get("ETag");
    if (!response.ok || !etag) throw new Error("A part failed to upload");
    completeParts.push({ part_number: i + 1, etag });
    bar.style.width = `${Math.round(((i + 1) / parts) * 100)}%`;
  }
  const completed = await fetch(`/v1/uploads/${initiated.upload_id}/complete`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ parts: completeParts }),
  }).then((r) => r.json());
  if (!completed.file_id) throw new Error(completed.detail || "Upload completion failed");

  const password = document.querySelector("#password").value;
  const downloads = Number(document.querySelector("#downloads").value);
  const expires = Number(document.querySelector("#expires").value);
  const share = await fetch(`/v1/files/${completed.file_id}/shares`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: password || null, max_downloads: downloads, expires_in_seconds: expires }),
  }).then((r) => r.json());

  const rawKey = await crypto.subtle.exportKey("raw", key);
  const keyText = Array.from(new Uint8Array(rawKey), (b) => b.toString(16).padStart(2, "0")).join("");
  const url = `${location.origin}/s/${share.token}#${keyText}`;
  document.querySelector("#shareUrl").value = url;
  document.querySelector("#result").hidden = false;
  status.textContent = "Encrypted drop created.";
}

document.querySelector("#upload").addEventListener("click", () => upload().catch((error) => {
  status.textContent = error.message;
}));
document.querySelector("#copy").addEventListener("click", async () => {
  await navigator.clipboard.writeText(document.querySelector("#shareUrl").value);
  status.textContent = "Link copied.";
});

async function redeem() {
  const match = location.pathname.match(/^\/s\/([^/]+)$/);
  if (!match) return;
  const keyText = location.hash.slice(1);
  if (!keyText) {
    status.textContent = "This link is missing its encryption key.";
    return;
  }
  const password = window.prompt("Password (leave blank if none)") || "";
  const params = password ? `?password=${encodeURIComponent(password)}` : "";
  status.textContent = "Redeeming encrypted drop...";
  const result = await fetch(`/s/${match[1]}${params}`).then((r) => r.json());
  if (!result.download_url) throw new Error(result.detail || "Share could not be redeemed");
  const cipherBlob = await fetch(result.download_url).then((r) => r.blob());
  const cipher = new Uint8Array(await cipherBlob.arrayBuffer());
  const keyBytes = new Uint8Array(keyText.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const partSize = 8 * 1024 * 1024;
  const parts = Math.ceil(cipher.length / partSize);
  const plainChunks = [];
  for (let i = 0; i < parts; i++) {
    const final = i === parts - 1;
    const envelope = cipher.slice(i * partSize, Math.min((i + 1) * partSize, cipher.length));
    plainChunks.push(await decryptChunk(envelope, key, i, final));
  }
  const plainLength = plainChunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const plain = new Uint8Array(plainLength);
  let offset = 0;
  for (const chunk of plainChunks) {
    plain.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([plain]));
  link.download = "vaultdrop-recovered";
  link.click();
  status.textContent = "Decrypted file downloaded.";
}

redeem().catch((error) => { status.textContent = error.message; });
