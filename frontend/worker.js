// root/frontend/worker.js
// Worker that loads crypto.js (Emscripten glue + wasm) and exposes raw-byte -> base64url handling

// IMPORTANT: crypto.js (EMCC modularized output) must be available next to this worker.
// It should export the factory function named `createCryptoModule` (set via -s EXPORT_NAME).
// The build script I suggested uses: -s MODULARIZE=1 -s EXPORT_NAME="createCryptoModule"

importScripts("crypto.js"); // loads the EMCC glue which defines createCryptoModule()

let ModulePromise = null;
let Module = null;       // Emscripten Module instance
let HEAPU8 = null;       // view into wasm memory

function toB64Url(bytes) {
  // bytes: Uint8Array
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  const b64 = btoa(binary);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function initWasm() {
  if (!ModulePromise) {
    // createCryptoModule() is the factory emitted by Emscripten when MODULARIZE=1
    ModulePromise = createCryptoModule(); // returns a Promise that resolves to the Module
  }

  Module = await ModulePromise;
  HEAPU8 = Module.HEAPU8;
  console.log("✅ Emscripten WASM module ready in worker");
}

// Helper to copy ArrayBuffer/Uint8Array into wasm heap
function allocAndWrite(bytes) {
  const ptr = Module._malloc(bytes.length);
  // Reacquire HEAPU8 in case memory grew
  HEAPU8 = Module.HEAPU8;
  if (!HEAPU8) throw new Error("HEAPU8 not available on Module");
  HEAPU8.set(bytes, ptr);
  return ptr;
}

// Helper to read bytes from heap (ptr -> Uint8Array copy)
function readHeapBytes(ptr, len) {
  HEAPU8 = Module.HEAPU8;
  return new Uint8Array(HEAPU8.subarray(ptr, ptr + len));
}

self.onmessage = async (event) => {
  const { cmd, scalar, challenge, state_id, _id } = event.data;

  if (!Module) await initWasm();

  if (cmd === "compute_v") {
    try {
      console.log("worker: compute_v called, scalar len:", scalar ? scalar.length : "null");
      const ptr = allocAndWrite(scalar);
      const outPtr = Module._malloc(64); // allocate output buffer (size depends on implementation)
      const rc = Module._compute_v_from_scalar(ptr, scalar.length, outPtr, 64);
      const written = rc > 0 ? rc : 32;
      const resultBytes = readHeapBytes(outPtr, written);
      const vB64 = toB64Url(resultBytes);
      console.log("worker: compute_v produced v len:", resultBytes.length);
      Module._free(ptr);
      Module._free(outPtr);
      postMessage({ v: vB64, _id });
    } catch (err) {
      console.error("worker compute_v error:", err);
      postMessage({ error: String(err), _id });
    }
  }

  else if (cmd === "initiate_login") {
    try {
      console.log("worker: initiate_login called, scalar len:", scalar ? scalar.length : "null");
      const ptr = allocAndWrite(scalar);
      const outPtr = Module._malloc(64);
      const statePtr = Module._malloc(4); // wasm writes a 32-bit state id here

      const rc = Module._initiate_login_from_scalar(ptr, scalar.length, outPtr, 64, statePtr);
      const written = rc > 0 ? rc : 32;
      const tBytes = readHeapBytes(outPtr, written);
      const tB64 = toB64Url(tBytes);
      // read state_id from the heap (little-endian)
      HEAPU8 = Module.HEAPU8;
      const dv = new DataView(HEAPU8.buffer, statePtr, 4);
      const state_id_val = dv.getUint32(0, true);

      console.log("worker: initiate_login produced t len:", tBytes.length, "state_id:", state_id_val);

      Module._free(ptr);
      Module._free(outPtr);
      Module._free(statePtr);
      postMessage({ t: tB64, state_id: state_id_val, _id });
    } catch (err) {
      console.error("worker initiate_login error:", err);
      postMessage({ error: String(err), _id });
    }
  }

  else if (cmd === "compute_s") {
    try {
      console.log("worker: compute_s called, state_id:", state_id, "challenge len:", challenge ? challenge.length : "null");
      const cPtr = allocAndWrite(challenge);
      const outPtr = Module._malloc(64);
      const rc = Module._compute_response_from_state(state_id, cPtr, challenge.length, outPtr, 64);
      const written = rc > 0 ? rc : 32;
      const sBytes = readHeapBytes(outPtr, written);
      const sB64 = toB64Url(sBytes);
      console.log("worker: compute_s produced s len:", sBytes.length);
      Module._free(cPtr);
      Module._free(outPtr);
      postMessage({ s: sB64, _id });
    } catch (err) {
      console.error("worker compute_s error:", err);
      postMessage({ error: String(err), _id });
    }
  } else {
    console.warn("worker: unknown cmd", cmd);
    postMessage({ error: "unknown_cmd", _id });
  }
};
