class ZKPLoader {
    constructor() {
        this.worker = null;
        this.wasmVerified = false;
    }

    async load() {
        try {
            // Load WASM and signature
            const [wasmResponse, sigResponse] = await Promise.all([
                fetch('crypto.wasm'),
                fetch('crypto.wasm.sig')
            ]);

            const wasmBuffer = await wasmResponse.arrayBuffer();
            const signature = await sigResponse.text();

            // Verify signature
            await this.verifyWasmSignature(wasmBuffer, signature);
            
            // Start worker
            this.worker = new Worker('worker.js');
            this.worker.postMessage({ type: 'INIT', wasmBuffer });
            
            return new Promise((resolve, reject) => {
                this.worker.onmessage = (e) => {
                    if (e.data.type === 'READY') {
                        this.wasmVerified = true;
                        resolve(this);
                    } else if (e.data.type === 'ERROR') {
                        reject(new Error(e.data.error));
                    }
                };
            });
            
        } catch (error) {
            console.error('Failed to load ZKP framework:', error);
            throw error;
        }
    }

    async verifyWasmSignature(wasmBuffer, signature) {
        // In production, use proper key management
        const publicKey = await this.getPublicKey();
        
        const wasmHash = await crypto.subtle.digest('SHA-256', wasmBuffer);
        const sigBuffer = this.base64urlToBuffer(signature);
        
        const isValid = await crypto.subtle.verify(
            'RSASSA-PKCS1-v1_5',
            publicKey,
            sigBuffer,
            wasmHash
        );
        
        if (!isValid) {
            throw new Error('WASM signature verification failed');
        }
    }

    async getPublicKey() {
        // Load public key for verification
        const response = await fetch('verify_wasm_public_key.pem');
        const pem = await response.text();
        
        // Convert PEM to ArrayBuffer
        const pemContents = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s/g, '');
        const binaryDer = this.base64urlToBuffer(pemContents);
        
        return await crypto.subtle.importKey(
            'spki',
            binaryDer,
            { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
            false,
            ['verify']
        );
    }

    base64urlToBuffer(base64url) {
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

    register(password) {
        return this._callWorker('REGISTER', { password });
    }

    loginInit(password) {
        return this._callWorker('LOGIN_INIT', { password });
    }

    loginResp(state, challenge) {
        return this._callWorker('LOGIN_RESP', { state, challenge });
    }

    _callWorker(type, data) {
        return new Promise((resolve, reject) => {
            if (!this.worker || !this.wasmVerified) {
                reject(new Error('WASM not loaded'));
                return;
            }

            const messageId = Math.random().toString(36);
            
            const handler = (e) => {
                if (e.data.messageId === messageId) {
                    this.worker.removeEventListener('message', handler);
                    if (e.data.error) {
                        reject(new Error(e.data.error));
                    } else {
                        resolve(e.data.result);
                    }
                }
            };
            
            this.worker.addEventListener('message', handler);
            this.worker.postMessage({ ...data, type, messageId });
        });
    }
}