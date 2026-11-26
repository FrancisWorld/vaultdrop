import test from "node:test";
import assert from "node:assert/strict";
import { ApiError, call, downloadFile, parseShareLocation, safeFilename, toParts, uploadFile } from "../vaultdrop/static/client.js";
import { importKey } from "../vaultdrop/static/crypto.js";

async function collect(iterable) {
  const out = [];
  for await (const item of iterable) out.push(item);
  return out;
}

test("toParts re-slices arbitrary chunks into exact part sizes", async () => {
  const chunks = [new Uint8Array(3).fill(1), new Uint8Array(9).fill(2), new Uint8Array(1).fill(3)];
  const parts = await collect(toParts((async function* () { yield* chunks; })(), 5));
  assert.deepEqual(parts.map((p) => p.length), [5, 5, 3]);
  assert.deepEqual(Array.from(parts[1]), [2, 2, 2, 2, 2]);
});

test("parseShareLocation and safeFilename", () => {
  assert.deepEqual(parseShareLocation("/s/abc_DEF-1", "#k=KEY_1"), { token: "abc_DEF-1", keyText: "KEY_1" });
  assert.deepEqual(parseShareLocation("/s/abc", ""), { token: "abc", keyText: null });
  assert.equal(parseShareLocation("/", ""), null);
  assert.equal(parseShareLocation("/s/a/b", ""), null);
  assert.equal(safeFilename("../../etc/passwd"), ".._.._etc_passwd");
  assert.equal(safeFilename(".."), "download");
  assert.equal(safeFilename("a\nb.txt"), "a_b.txt");
});

test("call turns error responses into ApiError", async () => {
  const api = async () => new Response(JSON.stringify({ detail: "nope" }), { status: 403 });
  await assert.rejects(() => call(api, "GET", "/x"), (e) => e instanceof ApiError && e.status === 403 && e.message === "nope");
  assert.equal(await call(async () => new Response(null, { status: 204 }), "DELETE", "/x"), null);
});

/** An in-memory stand-in for the VaultDrop API plus S3, enough to exercise resume logic. */
function fakeBackend({ failPutOnce = false } = {}) {
  const parts = new Map();
  const calls = [];
  let failed = !failPutOnce;
  const urls = (numbers) => numbers.map((n) => ({ part_number: n, url: `https://storage.test/p/${n}` }));
  const json = (data, status = 200) => new Response(JSON.stringify(data), { status });
  const state = { size: 0, partSize: 0 };
  const api = async (path, init) => {
    const body = init.body ? JSON.parse(init.body) : null;
    calls.push(`${init.method} ${path}`);
    if (path === "/v1/uploads") {
      state.size = body.size_bytes; state.partSize = body.part_size;
      const count = Math.ceil(body.size_bytes / body.part_size);
      return json({ upload_id: "u1", part_size: body.part_size, part_count: count, urls: urls([...Array(count).keys()].map((i) => i + 1)) });
    }
    if (path === "/v1/uploads/u1") {
      const count = Math.ceil(state.size / state.partSize);
      return json({
        part_size: state.partSize,
        stored_parts: [...parts].map(([n, p]) => ({ part_number: n, etag: p.etag, size_bytes: p.bytes.length })),
        pending_urls: urls([...Array(count).keys()].map((i) => i + 1).filter((n) => !parts.has(n))),
      });
    }
    if (path.startsWith("/v1/uploads/u1/parts/")) return json({ status: "recorded" });
    if (path === "/v1/uploads/u1/complete") return json({ file_id: "f1" });
    if (path === "/v1/files/f1/shares") return json({ token: "t".repeat(43) });
    return json({ detail: "unexpected" }, 500);
  };
  const storageFetch = async (url, init) => {
    const n = Number(url.split("/").pop());
    if (!failed) { failed = true; throw new Error("connection reset"); }
    const etag = `"etag-${n}"`;
    parts.set(n, { etag: etag.replaceAll('"', ""), bytes: init.body });
    return new Response(null, { status: 200, headers: { ETag: etag } });
  };
  return { api, storageFetch, parts, calls };
}

test("upload encrypts, splits into parts, records digests and shares", async () => {
  const backend = fakeBackend();
  const file = new File([new Uint8Array(3000).fill(7)], "report.bin", { type: "application/octet-stream" });
  const result = await uploadFile({ file, api: backend.api, storageFetch: backend.storageFetch, partSize: 1024, share: { maxDownloads: 2 } });
  assert.equal(result.fileId, "f1");
  assert.match(result.sharePath, /^\/s\/t{43}#k=[A-Za-z0-9_-]{43}$/);
  assert.ok(backend.parts.size >= 3);
  const stored = Buffer.concat([...backend.parts.keys()].sort().map((n) => backend.parts.get(n).bytes));
  assert.ok(!stored.includes(Buffer.from(new Uint8Array(50).fill(7))), "plaintext never reaches storage");
});

test("an interrupted upload resumes without re-sending finished parts", async () => {
  const backend = fakeBackend();
  const file = new File([new Uint8Array(4000).map((_, i) => i & 0xff)], "big.bin");
  let saved;
  let finished = 0;
  const crash = () => { if (++finished === 2) throw new Error("tab closed"); };
  await assert.rejects(() => uploadFile({
    file, api: backend.api, storageFetch: backend.storageFetch, partSize: 1024,
    onStart: (info) => { saved = info; }, onPart: crash,
  }), /tab closed/);
  assert.equal(backend.parts.size, 2);
  const before = new Map([...backend.parts].map(([n, p]) => [n, Buffer.from(p.bytes)]));

  let putCalls = 0;
  const counting = async (url, init) => { putCalls += 1; return backend.storageFetch(url, init); };
  const result = await uploadFile({
    file, api: backend.api, storageFetch: counting, partSize: 1024,
    key: await importKey(saved.keyText), resume: saved.uploadId,
  });
  assert.equal(result.keyText, saved.keyText);
  const total = Math.ceil(backend.parts.size);
  assert.equal(putCalls, total - 2, "only the missing parts were uploaded");
  for (const [n, bytes] of before) {
    assert.deepEqual(Buffer.from(backend.parts.get(n).bytes), bytes, "finished parts are byte-identical");
  }
});

test("a transient storage failure is retried", async () => {
  const backend = fakeBackend({ failPutOnce: true });
  const file = new File([new Uint8Array(100)], "small.bin");
  const result = await uploadFile({ file, api: backend.api, storageFetch: backend.storageFetch, partSize: 1024 });
  assert.equal(result.fileId, "f1");
});

test("resuming without the key is refused", async () => {
  await assert.rejects(() => uploadFile({ file: new File([], "x"), api: async () => {}, resume: "u1" }), /original key/);
});

test("download decrypts what upload produced and surfaces password-required", async () => {
  const backend = fakeBackend();
  const original = new Uint8Array(2500).map((_, i) => (i * 7) & 0xff);
  const file = new File([original], "doc.bin", { type: "application/x-test" });
  const up = await uploadFile({ file, api: backend.api, storageFetch: backend.storageFetch, partSize: 1024 });
  const ciphertext = Buffer.concat([...backend.parts.keys()].sort((a, b) => a - b).map((n) => backend.parts.get(n).bytes));
  const api = async (path, init) => {
    const body = JSON.parse(init.body);
    if (body.password !== "pw") return new Response(JSON.stringify({ detail: "Password required" }), { status: 401 });
    return new Response(JSON.stringify({ download_url: "https://storage.test/get" }), { status: 200 });
  };
  const storageFetch = async () => new Response(ciphertext, { status: 200 });
  await assert.rejects(() => downloadFile({ api, storageFetch, token: up.token, keyText: up.keyText }), (e) => e.status === 401);
  const got = await downloadFile({ api, storageFetch, token: up.token, keyText: up.keyText, password: "pw" });
  assert.equal(got.name, "doc.bin");
  assert.equal(got.type, "application/x-test");
  assert.deepEqual(new Uint8Array(await got.blob.arrayBuffer()), original);
  await assert.rejects(() => downloadFile({ api, storageFetch, token: up.token, keyText: "A".repeat(43), password: "pw" }), /modified|key/);
  await assert.rejects(() => downloadFile({ api, storageFetch: async () => new Response("", { status: 403 }), token: up.token, keyText: up.keyText, password: "pw" }), /refused/);
});
