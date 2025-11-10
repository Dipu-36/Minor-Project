/*
zkp-loader.js
--------------
Responsible for:
- Loading and verifying the signed WebAssembly crypto module
- Managing WebWorker that interacts with crypto.wasm
- Handling Argon2id password derivation
- Sending registration and login requests to the ZKP server
*/

import initArgon2 from "https://cdn.jsdelivr.net/npm/argon2-browser@1.18.0/dist/argon2-bundled.min.js";

const SERVER_URL = "https://127.0.0.1:8443"; // your Flask HTTPS server

// ===========================
// Load and verify the WASM module
// ===========================
async function loadWasm() {
  const response = await fetch("crypto.wasm");
  const wasmBinary = await response.arrayBuffer();

  // (Optional) Verify the wasm signature if crypto.wasm.sig exists
  try {
    const sig = await fetch("crypto.wasm.sig").then(r => r.arrayBuffer());
    const publicKeyResp = await fetch("wasm_pub.pem");
    const publicKey = await publicKeyResp.text();
    const key = await crypto.subtle.importKey(
      "spki",
      pemToArrayBuffer(publicKey),
      { name: "RSA-PSS", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const valid = await crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: 32 },
      key,
      sig,
      wasmBinary
    );
    if (!valid) throw new Error("Invalid WASM signature");
    log("✅ WASM signature verified");
  } catch (e) {
    console.warn("WASM signature verification skipped or failed:", e.message);
  }

  const wasmModule = await WebAssembly.compile(wasmBinary);
  const instance = await WebAssembly.instantiate(wasmModule, {});
  return instance.exports;
}

// Helper: PEM → ArrayBuffer
function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----.*?-----/g, "").replace(/\s+/g, "");
  const raw = atob(b64);
  const buf = new ArrayBuffer(raw.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < raw.length; i++) view[i] = raw.charCodeAt(i);
  return buf;
}

// ===========================
// Worker Setup
// ===========================
const worker = new Worker("worker.js");

// ===========================
// Logging
// ===========================
function log(msg) {
  const el = document.getElementById("log");
  el.textContent += msg + "\n";
}

// ===========================
// Argon2id KDF
// ===========================
async function deriveScalar(password, saltBase64) {
  const salt = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
  const result = await initArgon2.hash({
    pass: password,
    salt,
    type: initArgon2.ArgonType.Argon2id,
    hashLen: 32,
    time: 3,
    mem: 4096,
  });
  return result.hash; // Uint8Array(32)
}

// ===========================
// Registration
// ===========================
async function registerUser() {
  const user = document.getElementById("reg-user").value;
  const password = document.getElementById("reg-pass").value;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltB64 = btoa(String.fromCharCode(...salt));

  const scalar = await deriveScalar(password, saltB64);

  // Send scalar to worker to compute verifier v = g^x
  const vB64 = await new Promise((resolve) => {
    worker.onmessage = e => resolve(e.data.v);
    worker.postMessage({ cmd: "compute_v", scalar });
  });

  const res = await fetch(`${SERVER_URL}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user_id: user, v: vB64, salt: saltB64 }),
  });
  log(`Registration: ${res.status}`);
}

// ===========================
// Login
// ===========================
async function loginUser() {
  const user = document.getElementById("login-user").value;
  const password = document.getElementById("login-pass").value;

  // Retrieve user salt from server (via a simple endpoint you may add later)
  const userRes = await fetch(`${SERVER_URL}/user_salt?user=${user}`);
  const { salt } = await userRes.json();
  const scalar = await deriveScalar(password, salt);

  // Step 1: get t = g^r from worker
  const { t, state_id } = await new Promise(resolve => {
    worker.onmessage = e => resolve(e.data);
    worker.postMessage({ cmd: "initiate_login", scalar });
  });

  // Step 2: send t to server → receive challenge c and session_id
  const res1 = await fetch(`${SERVER_URL}/login/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user_id: user, t }),
  });
  const { challenge, session_id } = await res1.json();
  const challengeBytes = Uint8Array.from(atob(challenge), c => c.charCodeAt(0));

  // Step 3: compute s = r + c*x
  const sB64 = await new Promise(resolve => {
    worker.onmessage = e => resolve(e.data.s);
    worker.postMessage({ cmd: "compute_s", state_id, challenge: challengeBytes });
  });

  // Step 4: send s to server to verify
  const res2 = await fetch(`${SERVER_URL}/login/finish`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user_id: user, session_id, s: sB64 }),
  });
  log(`Login result: ${res2.status}`);
}

// ===========================
// UI bindings
// ===========================
document.getElementById("reg-btn").onclick = registerUser;
document.getElementById("login-btn").onclick = loginUser;

log("🔧 Frontend loaded");

