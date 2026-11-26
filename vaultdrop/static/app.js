import { ApiError, call, downloadFile, parseShareLocation, safeFilename, uploadFile } from "./client.js";

const $ = (selector) => document.querySelector(selector);
const status = $("#status");
const show = (name, visible) => { $(name).hidden = !visible; };
const say = (text) => { status.textContent = text; };

const api = (path, init) => fetch(path, { ...init, credentials: "same-origin" });

async function refreshSession() {
  try {
    await call(api, "GET", "/v1/auth/me");
    show("#auth", false);
    show("#send", true);
  } catch {
    show("#send", false);
    show("#auth", true);
  }
}

async function authenticate(path) {
  try {
    await call(api, "POST", path, { username: $("#username").value, password: $("#accountPassword").value });
    $("#accountPassword").value = "";
    say("");
    await refreshSession();
  } catch (error) {
    say(error.message);
  }
}

$("#login").addEventListener("click", () => authenticate("/v1/auth/login"));
$("#register").addEventListener("click", () => authenticate("/v1/auth/register"));
$("#logout").addEventListener("click", async () => {
  await call(api, "POST", "/v1/auth/logout");
  await refreshSession();
});
$("#file").addEventListener("change", () => {
  $("#fileName").textContent = $("#file").files[0]?.name || "Choose or drop a file";
});

$("#upload").addEventListener("click", async () => {
  const file = $("#file").files[0];
  if (!file) return say("Choose a file first.");
  show("#progress", true);
  say("Encrypting and uploading...");
  try {
    const result = await uploadFile({
      file,
      api,
      share: {
        password: $("#password").value,
        maxDownloads: Number($("#downloads").value) || null,
        expiresInSeconds: Number($("#expires").value),
      },
      onPart: (part, total) => { $("#bar").style.width = `${Math.round((part / total) * 100)}%`; },
    });
    $("#shareUrl").value = `${location.origin}${result.sharePath}`;
    show("#result", true);
    say("Encrypted drop created. Send the whole link: the part after # is the key.");
  } catch (error) {
    say(error.message);
  }
});

$("#copy").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("#shareUrl").value);
  say("Link copied.");
});

async function receive(target) {
  show("#receive", true);
  if (!target.keyText) return say("This link is missing its encryption key.");
  $("#download").addEventListener("click", async () => {
    say("Downloading and decrypting...");
    try {
      const { name, blob } = await downloadFile({
        api, token: target.token, password: $("#sharePassword").value, keyText: target.keyText,
      });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = safeFilename(name);
      link.click();
      URL.revokeObjectURL(link.href);
      say("Decrypted file saved.");
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        show("#passwordRow", true);
        say("This drop needs a password.");
      } else {
        say(error.message);
      }
    }
  });
}

const target = parseShareLocation(location.pathname, location.hash);
if (target) receive(target); else refreshSession();
