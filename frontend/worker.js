// root/frontend/worker.js
// Worker that loads crypto.wasm and exposes raw-byte -> base64url handling

let wasmExports;
let memory;

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
  const response = await fetch("crypto.wasm");
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  // Provide imports if required by your wasm (e.g., env) — empty for now
  const instance = await WebAssembly.instantiate(module, {});
  wasmExports = instance.exports;
  memory = wasmExports.memory;
  console.log("✅ WASM loaded in worker");
}

self.onmessage = async (event) => {
  const { cmd, scalar, challenge, state_id } = event.data;

  if (!wasmExports) await initWasm();

  // Helper to copy ArrayBuffer/Uint8Array into wasm heap
  function allocAndWrite(bytes) {
    const ptr = wasmExports._malloc(bytes.length);
    new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
    return ptr;
  }

  if (cmd === "compute_v") {
    // scalar is Uint8Array
    const ptr = allocAndWrite(scalar);
    const outPtr = wasmExports._malloc(64); // allocate output buffer (size depends on implementation)
    const rc = wasmExports._compute_v_from_scalar(ptr, scalar.length, outPtr, 64);
    // rc should be number of bytes written; if not, we assume 32 or 64
    const written = rc > 0 ? rc : 32;
    const resultBytes = new Uint8Array(memory.buffer, outPtr, written);
    const vB64 = toB64Url(resultBytes);
    wasmExports._free(ptr);
    wasmExports._free(outPtr);
    postMessage({ v: vB64 });
  }

  else if (cmd === "initiate_login") {
    const ptr = allocAndWrite(scalar);
    const outPtr = wasmExports._malloc(64);
    const statePtr = wasmExports._malloc(4); // wasm returns an integer handle by writing to this ptr

    const rc = wasmExports._initiate_login_from_scalar(ptr, scalar.length, outPtr, 64, statePtr);
    const written = rc > 0 ? rc : 32;
    const tBytes = new Uint8Array(memory.buffer, outPtr, written);
    const tB64 = toB64Url(tBytes);
    const state_id = new DataView(memory.buffer).getUint32(statePtr, true);

    wasmExports._free(ptr);
    wasmExports._free(outPtr);
    wasmExports._free(statePtr);
    postMessage({ t: tB64, state_id });
  }

  else if (cmd === "compute_s") {
    const cPtr = allocAndWrite(challenge);
    const outPtr = wasmExports._malloc(64);
    const rc = wasmExports._compute_response_from_state(state_id, cPtr, challenge.length, outPtr, 64);
    const written = rc > 0 ? rc : 32;
    const sBytes = new Uint8Array(memory.buffer, outPtr, written);
    const sB64 = toB64Url(sBytes);

    wasmExports._free(cPtr);
    wasmExports._free(outPtr);
    postMessage({ s: sB64 });
  }
};
