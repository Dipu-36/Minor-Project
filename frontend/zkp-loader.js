/*
zkp-loader.js
--------------
Responsible for:
- Loading and verifying the signed WebAssembly crypto module
- Managing WebWorker that interacts with crypto.wasm
- Handling Argon2id password derivation
- Sending registration and login requests to the ZKP server
*/

// =======================================================
//  Argon2 Loader (Safe ESM → fallback to UMD)
// =======================================================

let argon2lib = null;

async function ensureArgon2() {
  if (argon2lib) return argon2lib;

  // --- Try modern ESM build first ---
  try {
    argon2lib = await import(
      "https://cdn.jsdelivr.net/npm/argon2-browser@1.18.0/dist/argon2-esm.min.js"
    );
    console.info("argon2 (ESM) loaded");
    return argon2lib;
  } catch (e) {
    console.warn("argon2 ESM load failed, falling back to UMD:", e);
  }

  // --- Fallback: bundled UMD build (global) ---
  await new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = "https://cdn.jsdelivr.net/npm/argon2-browser@1.18.0/dist/argon2-bundled.min.js";
    s.onload = () => {
      const g = window.argon2 || (window.A && window.A.argon2);
      if (!g) return reject(new Error("UMD loaded but no global argon2 found"));
      argon2lib = g;
      console.info("argon2 (bundled) loaded via fallback");
      resolve();
    };
    s.onerror = reject;
    document.head.appendChild(s);
  });

  return argon2lib;
}


// =======================================================
//  Worker Setup
// =======================================================

const worker = new Worker("worker.js");

// RPC helper: send message to worker with unique id and wait for matching reply
function callWorker(msg, timeout = 7000) {
  return new Promise((resolve, reject) => {
    const id = Math.random().toString(36).slice(2);
    msg._id = id;

    function onMsg(e) {
      const data = e.data;
      if (!data || data._id !== id) return; // not our message
      worker.removeEventListener("message", onMsg);
      clearTimeout(tid);
      resolve(data);
    }

    const tid = setTimeout(() => {
      worker.removeEventListener("message", onMsg);
      reject(new Error("worker timeout"));
    }, timeout);

    worker.addEventListener("message", onMsg);
    worker.postMessage(msg);
  });
}


// =======================================================
//  Logging
// =======================================================
function log(msg) {
  const el = document.getElementById("log");
  if (el) el.textContent += msg + "\n";
  console.log("[zkp-loader]", msg);
}


// =======================================================
//  Helper: PEM → ArrayBuffer
// =======================================================
function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----.*?-----/g, "").replace(/\s+/g, "");
  const raw = atob(b64);
  const buf = new ArrayBuffer(raw.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < raw.length; i++) view[i] = raw.charCodeAt(i);
  return buf;
}


// =======================================================
//  Helper: base64url → Uint8Array
// =======================================================
function decodeB64UrlToUint8(b64url) {
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  const raw = atob(b64);
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

// =======================================================
//  Helper: bytes -> base64url string
// =======================================================
function bytesToBase64Url(bytes) {
  // bytes: Uint8Array
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, Array.prototype.slice.call(bytes.subarray(i, i + chunkSize)));
  }
  const b64 = btoa(binary);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}


// =======================================================
//  Argon2id KDF
// =======================================================
async function deriveScalar(password, saltBase64) {
  const salt = Uint8Array.from(atob(saltBase64), (c) => c.charCodeAt(0));
  const lib = await ensureArgon2();

  const hashFn = lib.hash || (lib.argon2 && lib.argon2.hash);
  const ArgonType = lib.ArgonType || (lib.argon2 && lib.argon2.ArgonType);

  if (!hashFn) throw new Error("argon2 hash function not available");

  const result = await hashFn({
    pass: password,
    salt,
    type: ArgonType ? ArgonType.Argon2id : 1,
    hashLen: 32,
    time: 3,
    mem: 4096,
  });

  return result.hash; // Uint8Array(32)
}


// =======================================================
//  Server URL
// =======================================================
const SERVER_URL = "https://127.0.0.1:8443";


// =======================================================
//  Registration
// =======================================================
async function registerUser() {
  try {
    const user = document.getElementById("reg-user").value;
    const password = document.getElementById("reg-pass").value;

    if (!user || !password) {
      log(" username or password empty");
      return;
    }

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const saltB64 = btoa(String.fromCharCode(...salt));

    log("KDF: deriving scalar...");
    const scalar = await deriveScalar(password, saltB64);
    log("KDF: done. scalar length: " + (scalar ? scalar.length : "null"));

    // compute v = g^x
    log("worker: compute_v asked");
    const workerResp = await callWorker({ cmd: "compute_v", scalar });

    // workerResp should contain { v: "<base64url-string>" }
    // Normalize to a string (in case the worker returned bytes)
    let v = workerResp && workerResp.v;
    if (!v && workerResp && workerResp.vBytes) {
      // some older worker versions might return raw bytes as vBytes
      v = bytesToBase64Url(new Uint8Array(workerResp.vBytes));
    }

    // if v is a typed array/object, coerce to base64url string
    if (v && (v instanceof Uint8Array || (v.buffer && v.buffer instanceof ArrayBuffer))) {
      v = bytesToBase64Url(new Uint8Array(v));
    }

    // Final guard: if it's still an object, stringify for debug (but avoid sending raw object)
    if (typeof v !== "string") {
      log(" compute_v returned non-string. coercing to JSON string for debug.");
      v = JSON.stringify(v);
    }

    log("worker: compute_v returned (v present?): " + (!!v));

    log("DEBUG: user=" + user + " salt_len=" + saltB64.length + " v_len=" + (v ? v.length : "null"));
    console.log("DEBUG payload:", { user_id: user, v, salt: saltB64 });

    const res = await fetch(`${SERVER_URL}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_id: user, v, salt: saltB64 }),
    });

    log(`Registration: ${res.status}`);
    const body = await res.text();
    log("Registration response body: " + body);
  } catch (err) {
    console.error("registerUser error", err);
    log("Registration failed: " + (err && err.message));
  }
}


// =======================================================
//  Login
// =======================================================
async function loginUser() {
  try {
    const user = document.getElementById("login-user").value;
    const password = document.getElementById("login-pass").value;

    if (!user || !password) {
      log(" login username or password empty");
      return;
    }

    // Step 1: get salt from server
    log("Fetching salt for user: " + user);
    const userRes = await fetch(`${SERVER_URL}/user_salt?user=${user}`);
    if (!userRes.ok) {
      log(" Failed to get salt: " + userRes.status);
      return;
    }
    const { salt } = await userRes.json();
    log("Got salt (len): " + (salt ? salt.length : "null"));

    const scalar = await deriveScalar(password, salt);
    log("KDF: scalar derived len " + (scalar ? scalar.length : "null"));

    // Step 2: generate t = g^r
    log("worker: initiate_login asked");
    const init = await callWorker({ cmd: "initiate_login", scalar });
    log("worker: initiate_login returned keys: " + Object.keys(init).join(","));
    const t = init.t;
    const state_id = init.state_id;

    // Step 3: send t → get challenge
    log("Sending t to server for challenge");
    const res1 = await fetch(`${SERVER_URL}/login/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_id: user, t }),
    });

    if (!res1.ok) {
      log("server rejected t: " + res1.status);
      const txt = await res1.text();
      log("server body: " + txt);
      return;
    }

    const { challenge, session_id } = await res1.json();
    log("Received challenge (len): " + (challenge ? challenge.length : "null") + " session_id: " + session_id);

    const challengeBytes = decodeB64UrlToUint8(challenge);

    // Step 4: compute s
    log("worker: compute_s asked");
    const resp = await callWorker({
      cmd: "compute_s",
      state_id,
      challenge: challengeBytes,
    });

    let s = resp.s;
    if (!s && resp.sBytes) s = bytesToBase64Url(new Uint8Array(resp.sBytes));
    if (s && (s instanceof Uint8Array || (s.buffer && s.buffer instanceof ArrayBuffer))) s = bytesToBase64Url(new Uint8Array(s));
    if (typeof s !== "string") s = JSON.stringify(s);

    // Step 5: send s to server
    log("Sending s to server for verification");
    const res2 = await fetch(`${SERVER_URL}/login/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_id: user, session_id, s }),
    });

    log(`Login result: ${res2.status}`);
    const body = await res2.text();
    log("Login response body: " + body);
  } catch (err) {
    console.error("loginUser error", err);
    log("Login failed: " + (err && err.message));
  }
}


// =======================================================
//  UI Bindings
// =======================================================
document.getElementById("reg-btn").onclick = registerUser;
document.getElementById("login-btn").onclick = loginUser;

log("🔧 Frontend loaded");
