// End-to-end check against a running VaultDrop stack, using the same crypto and
// client modules the browser loads. Usage: node scripts/e2e.mjs [baseUrl]
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { downloadFile, uploadFile } from "../vaultdrop/static/client.js";
import { importKey } from "../vaultdrop/static/crypto.js";

const base = process.argv[2] || "http://127.0.0.1:55001";
let cookie = "";

async function api(path, init = {}) {
  const response = await fetch(base + path, {
    ...init,
    headers: { ...init.headers, ...(cookie ? { Cookie: cookie } : {}), Origin: base },
  });
  const set = response.headers.get("set-cookie");
  if (set) cookie = set.split(";")[0];
  return response;
}

const step = (message) => console.log(`- ${message}`);
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");

const user = `e2e-${randomBytes(4).toString("hex")}`;
const registered = await api("/v1/auth/register", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ username: user, password: randomBytes(12).toString("hex") }),
});
assert.equal(registered.status, 200, "register");
step(`registered ${user}`);

const original = randomBytes(20 * 1024 * 1024 + 123);
const file = new File([original], "quarterly report.bin", { type: "application/octet-stream" });
step(`plaintext ${original.length} bytes, sha256 ${sha(original).slice(0, 16)}...`);

// 1. Upload, killing the "tab" after the first part.
let saved;
const crash = (part) => { if (part === 1) throw new Error("simulated tab close"); };
await assert.rejects(
  () => uploadFile({ file, api, onStart: (info) => { saved = info; }, onPart: crash }),
  /simulated tab close/,
);
step(`interrupted after part 1 (upload ${saved.uploadId})`);

// 2. Resume with the saved key; only missing parts go over the wire.
let puts = 0;
const countingFetch = (url, init) => { if (init?.method === "PUT") puts += 1; return fetch(url, init); };
const result = await uploadFile({
  file, api, storageFetch: countingFetch, key: await importKey(saved.keyText), resume: saved.uploadId,
  share: { password: "open sesame", maxDownloads: 2, expiresInSeconds: 3600 },
});
const stored = await (await api("/v1/files")).json();
assert.equal(stored.length, 1);
step(`resumed: ${puts} part(s) re-sent, stored ${stored[0].size_bytes} ciphertext bytes (sha256 ${stored[0].sha256.slice(0, 16)}...)`);
assert.ok(stored[0].size_bytes > original.length, "ciphertext carries framing overhead");
assert.notEqual(stored[0].filename, file.name, "the real file name is not sent in clear");

// 3. Download as a recipient: anonymous session, password and the key from the link.
const [, token] = /^\/s\/([^#]+)#k=(.+)$/.exec(result.sharePath);
const keyText = result.keyText;
const jar = cookie;
cookie = "";
const page = await api(`/s/${token}`);
assert.equal(page.status, 200);
assert.match(await page.text(), /VaultDrop/);

await assert.rejects(() => downloadFile({ api, token, keyText }), (e) => e.status === 401);
await assert.rejects(() => downloadFile({ api, token, keyText, password: "wrong" }), (e) => e.status === 403);
step("share refuses a missing and a wrong password");

const received = await downloadFile({ api, token, keyText, password: "open sesame" });
const bytes = new Uint8Array(await received.blob.arrayBuffer());
assert.equal(received.name, "quarterly report.bin");
assert.equal(bytes.length, original.length);
assert.equal(sha(bytes), sha(original));
step(`downloaded and decrypted: name restored, ${bytes.length} bytes, sha256 matches`);

// 4. A wrong key must fail authentication, and the download limit must hold.
const wrongKey = "A".repeat(43);
await assert.rejects(() => downloadFile({ api, token, keyText: wrongKey, password: "open sesame" }), /modified|wrong key/);
const second = await api("/v1/shares/redeem", {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ token, password: "open sesame" }),
});
assert.equal(second.status, 404, "limit of 2 downloads is exhausted (the wrong-key attempt consumed one)");
step("wrong key rejected; download limit enforced");

cookie = jar;
const audit = await (await api("/v1/audit")).json();
step(`audit trail: ${[...new Set(audit.map((e) => e.action))].sort().join(", ")}`);
console.log("e2e ok");
