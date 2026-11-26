// Upload / download flows shared by the web UI and the end-to-end script. All I/O is
// injected (`api`, `storageFetch`) so the same code runs in a browser and in Node.
import { exportKey, generateKey, importKey, iterate, openFile, sealFile } from "./crypto.js";

export const DEFAULT_PART_SIZE = 8 * 1024 * 1024;
const PUT_ATTEMPTS = 3;

export class ApiError extends Error {
  constructor(status, detail) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
  }
}

/** `api(path, init)` is fetch-like and already carries the session cookie and base URL. */
export async function call(api, method, path, body, headers = {}) {
  const init = { method, headers: { ...headers } };
  if (body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const response = await api(path, init);
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new ApiError(response.status, data.detail || `Request failed (${response.status})`);
  return data;
}

export async function sha256Hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}

function concat(pieces, length) {
  const out = new Uint8Array(length);
  let offset = 0;
  for (const piece of pieces) {
    out.set(piece, offset);
    offset += piece.length;
  }
  return out;
}

/** Re-slice a stream of arbitrary-sized chunks into storage parts of exactly `partSize` bytes. */
export async function* toParts(chunks, partSize) {
  let pieces = [];
  let length = 0;
  for await (const chunk of chunks) {
    let view = chunk;
    while (view.length) {
      const room = partSize - length;
      const piece = view.subarray(0, room);
      pieces.push(piece);
      length += piece.length;
      view = view.subarray(piece.length);
      if (length === partSize) {
        yield concat(pieces, length);
        pieces = [];
        length = 0;
      }
    }
  }
  if (length) yield concat(pieces, length);
}

async function putPart(storageFetch, url, bytes) {
  let lastError;
  for (let attempt = 1; attempt <= PUT_ATTEMPTS; attempt++) {
    try {
      const response = await storageFetch(url, { method: "PUT", body: bytes });
      const etag = response.headers.get("ETag");
      if (response.ok && etag) return etag;
      lastError = new Error(response.ok
        ? "Storage did not expose the ETag header (check the bucket CORS rules)"
        : `Storage rejected a part (${response.status})`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 200 * attempt));
  }
  throw lastError;
}

/**
 * Encrypt `file` in the caller's memory-bounded chunks and upload it as a multipart
 * upload. `onStart({ uploadId, keyText })` fires once the upload exists, so a caller can
 * persist it; pass the same `key` (a CryptoKey from `importKey`) and `resume: uploadId`
 * later to continue after an interruption: parts storage already holds are re-derived
 * (encryption is deterministic) and skipped.
 */
export async function uploadFile({
  file, api, storageFetch = fetch, share = {}, key = null, resume = null,
  partSize = DEFAULT_PART_SIZE, onStart = () => {}, onPart = () => {},
  filename = `${crypto.randomUUID()}.vdrop`,
}) {
  if (resume && !key) throw new Error("Resuming needs the original key");
  key = key || await generateKey();
  const sealed = await sealFile(file, key, { name: file.name, type: file.type });

  let uploadId;
  let urls = new Map();
  const stored = new Map();
  if (resume) {
    uploadId = resume;
    const status = await call(api, "GET", `/v1/uploads/${uploadId}`);
    status.pending_urls.forEach((entry) => urls.set(entry.part_number, entry.url));
    status.stored_parts.forEach((part) => stored.set(part.part_number, part));
    partSize = status.part_size;
  } else {
    const ticket = await call(api, "POST", "/v1/uploads",
      { filename, size_bytes: sealed.totalLength, part_size: partSize },
      { "Idempotency-Key": crypto.randomUUID() });
    uploadId = ticket.upload_id;
    ticket.urls.forEach((entry) => urls.set(entry.part_number, entry.url));
  }
  await onStart({ uploadId, keyText: await exportKey(key) });

  const completed = [];
  let number = 0;
  for await (const bytes of toParts(sealed.chunks(), partSize)) {
    number += 1;
    const held = stored.get(number);
    let etag;
    if (held && held.size_bytes === bytes.length) {
      etag = held.etag;
    } else {
      const url = urls.get(number);
      if (!url) throw new Error(`No upload URL for part ${number}`);
      etag = await putPart(storageFetch, url, bytes);
    }
    await call(api, "POST", `/v1/uploads/${uploadId}/parts/${number}`,
      { etag, size_bytes: bytes.length, sha256: await sha256Hex(bytes) });
    completed.push({ part_number: number, etag });
    await onPart(number, Math.ceil(sealed.totalLength / partSize));
  }

  const finished = await call(api, "POST", `/v1/uploads/${uploadId}/complete`, { parts: completed });
  const created = await call(api, "POST", `/v1/files/${finished.file_id}/shares`, {
    password: share.password || null,
    max_downloads: share.maxDownloads ?? null,
    expires_in_seconds: share.expiresInSeconds ?? null,
  });
  const keyText = await exportKey(key);
  return { uploadId, fileId: finished.file_id, token: created.token, keyText, sharePath: `/s/${created.token}#k=${keyText}` };
}

export function parseShareLocation(pathname, hash) {
  const match = /^\/s\/([A-Za-z0-9_-]+)$/.exec(pathname);
  const key = /^#k=([A-Za-z0-9_-]+)$/.exec(hash);
  return match ? { token: match[1], keyText: key ? key[1] : null } : null;
}

/** Redeem a share, fetch the ciphertext from storage and decrypt it. */
export async function downloadFile({ api, storageFetch = fetch, token, password, keyText }) {
  const key = await importKey(keyText);
  const redeemed = await call(api, "POST", "/v1/shares/redeem", { token, password: password || null });
  const response = await storageFetch(redeemed.download_url);
  if (!response.ok) throw new Error(`Storage refused the download (${response.status})`);
  const { header, plaintext } = await openFile(iterate(response.body), key);
  const chunks = [];
  for await (const chunk of plaintext()) chunks.push(chunk);
  return { name: header.name, type: header.type, blob: new Blob(chunks, { type: header.type || "application/octet-stream" }) };
}

export function safeFilename(name) {
  const cleaned = name.replace(/[\u0000-\u001f\u007f/\\]/g, "_").trim();
  return cleaned && cleaned !== "." && cleaned !== ".." ? cleaned.slice(0, 200) : "download";
}
