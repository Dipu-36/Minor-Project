let wasmModule = null;

// Message handler
self.onmessage = async function(e) {
    const { type, messageId } = e.data;
    
    try {
        let result;
        
        switch (type) {
            case 'INIT':
                result = await initWasm(e.data.wasmBuffer);
                break;
            case 'REGISTER':
                result = await handleRegister(e.data.password);
                break;
            case 'LOGIN_INIT':
                result = await handleLoginInit(e.data.password);
                break;
            case 'LOGIN_RESP':
                result = await handleLoginResp(e.data.state, e.data.challenge);
                break;
            default:
                throw new Error(`Unknown message type: ${type}`);
        }
        
        self.postMessage({ type, messageId, result });
        
    } catch (error) {
        self.postMessage({ type, messageId, error: error.message });
    }
};

async function initWasm(wasmBuffer) {
    const imports = {
        env: {
            emscripten_random_buf: (ptr, size) => {
                const randomValues = crypto.getRandomValues(new Uint8Array(size));
                wasmModule.HEAPU8.set(randomValues, ptr);
            }
        }
    };
    
    wasmModule = await WebAssembly.instantiate(wasmBuffer, imports);
    return { status: 'ready' };
}

async function handleRegister(password) {
    const passwordEncoded = new TextEncoder().encode(password);
    const passwordPtr = wasmModule._malloc(passwordEncoded.length);
    wasmModule.HEAPU8.set(passwordEncoded, passwordPtr);
    
    const outputPtr = wasmModule._malloc(64); // Enough for base64
    
    const result = wasmModule._compute_v_from_password(
        passwordPtr, 
        passwordEncoded.length, 
        outputPtr, 
        64
    );
    
    let v = null;
    if (result === 0) {
        v = wasmModule.UTF8ToString(outputPtr);
    }
    
    // Cleanup
    wasmModule._free(passwordPtr);
    wasmModule._free(outputPtr);
    
    if (result !== 0) {
        throw new Error('Registration failed');
    }
    
    return { v };
}

async function handleLoginInit(password) {
    const passwordEncoded = new TextEncoder().encode(password);
    const passwordPtr = wasmModule._malloc(passwordEncoded.length);
    wasmModule.HEAPU8.set(passwordEncoded, passwordPtr);
    
    const outputPtr = wasmModule._malloc(64);
    const statePtr = wasmModule._malloc(4);
    
    const result = wasmModule._initiate_login_from_password(
        passwordPtr,
        passwordEncoded.length,
        outputPtr,
        64,
        statePtr
    );
    
    let t = null;
    let state = null;
    if (result === 0) {
        t = wasmModule.UTF8ToString(outputPtr);
        state = wasmModule.HEAPU32[statePtr >> 2];
    }
    
    // Cleanup
    wasmModule._free(passwordPtr);
    wasmModule._free(outputPtr);
    wasmModule._free(statePtr);
    
    if (result !== 0) {
        throw new Error('Login initiation failed');
    }
    
    return { t, state };
}

async function handleLoginResp(state, challenge) {
    const challengeBuffer = base64urlToBuffer(challenge);
    const challengePtr = wasmModule._malloc(challengeBuffer.length);
    wasmModule.HEAPU8.set(new Uint8Array(challengeBuffer), challengePtr);
    
    const outputPtr = wasmModule._malloc(64);
    
    const result = wasmModule._compute_response_from_state(
        state,
        challengePtr,
        challengeBuffer.length,
        outputPtr,
        64
    );
    
    let s = null;
    if (result === 0) {
        s = wasmModule.UTF8ToString(outputPtr);
    }
    
    // Cleanup
    wasmModule._free(challengePtr);
    wasmModule._free(outputPtr);
    
    if (result !== 0) {
        throw new Error('Response computation failed');
    }
    
    return { s };
}

function base64urlToBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - (base64.length % 4)) % 4);
    const base64WithPadding = base64 + padding;
    const binary = atob(base64WithPadding);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}