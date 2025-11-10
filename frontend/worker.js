/*
worker.js
----------
Handles WebAssembly crypto operations off the main thread.
Receives Argon2id scalar from zkp-loader.js and calls into crypto.wasm.
*/

let wasmExports;
let memory;

async function initWasm() {
  const response = await fetch("crypto.wasm");
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module, {});
  wasmExports = instance.exports;
  memory = wasmExports.memory;
  console.log("✅ WASM loaded in worker");
}

self.onmessage = async (event) => {
  const { cmd, scalar, challenge, state_id } = event.data;

  if (!wasmExports) await initWasm();

  if (cmd === "compute_v") {
    const ptr = wasmExports._malloc(scalar.length);
    new Uint8Array(memory.buffer, ptr, scalar.length).set(scalar);
    const outPtr = wasmExports._malloc(128);

    const rc = wasmExports._compute_v_from_scalar(ptr, scalar.length, outPtr, 128);
    const resultBytes = new Uint8Array(memory.buffer, outPtr, 64);
    const vB64 = new TextDecoder().decode(resultBytes).replace(/\0/g, "");

    wasmExports._free(ptr);
    wasmExports._free(outPtr);
    postMessage({ v: vB64 });
  }

  else if (cmd === "initiate_login") {
    const ptr = wasmExports._malloc(scalar.length);
    new Uint8Array(memory.buffer, ptr, scalar.length).set(scalar);
    const outPtr = wasmExports._malloc(128);
    const statePtr = wasmExports._malloc(4);

    const rc = wasmExports._initiate_login_from_scalar(ptr, scalar.length, outPtr, 128, statePtr);
    const tBytes = new Uint8Array(memory.buffer, outPtr, 64);
    const tB64 = new TextDecoder().decode(tBytes).replace(/\0/g, "");
    const state_id = new DataView(memory.buffer).getUint32(statePtr, true);

    wasmExports._free(ptr);
    wasmExports._free(outPtr);
    wasmExports._free(statePtr);
    postMessage({ t: tB64, state_id });
  }

  else if (cmd === "compute_s") {
    const cPtr = wasmExports._malloc(challenge.length);
    new Uint8Array(memory.buffer, cPtr, challenge.length).set(challenge);
    const outPtr = wasmExports._malloc(128);

    const rc = wasmExports._compute_response_from_state(state_id, cPtr, challenge.length, outPtr, 128);
    const sBytes = new Uint8Array(memory.buffer, outPtr, 64);
    const sB64 = new TextDecoder().decode(sBytes).replace(/\0/g, "");

    wasmExports._free(cPtr);
    wasmExports._free(outPtr);
    postMessage({ s: sB64 });
  }
};

