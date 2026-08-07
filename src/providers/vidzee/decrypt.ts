function toPlainArrayBuffer(u8: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(u8.byteLength);
  new Uint8Array(ab).set(u8);
  return ab;
}

export async function decrypt(
    encryptedData: string,
    decryptionKey: string
): Promise<string> {
    try {
        if (!encryptedData || !decryptionKey) return '';

        const decoded = atob(encryptedData);
        const [ivBase64, cipherBase64] = decoded.split(':');
        if (!ivBase64 || !cipherBase64) return '';

        const iv = Uint8Array.from(atob(ivBase64), (c) => c.charCodeAt(0));
        const cipherBytes = Uint8Array.from(atob(cipherBase64), (c) =>
            c.charCodeAt(0)
        );

        const keyBytes = getKeyBytes(decryptionKey);

        // Convert to plain ArrayBuffer copies to avoid SharedArrayBuffer in some environments
        const ivArrayBuffer = toPlainArrayBuffer(iv);
        const cipherArrayBuffer = toPlainArrayBuffer(cipherBytes);
        const keyArrayBuffer = toPlainArrayBuffer(keyBytes);

        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            keyArrayBuffer,
            { name: 'AES-CBC' },
            false,
            ['decrypt']
        );

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv: new Uint8Array(ivArrayBuffer) },
            cryptoKey,
            cipherArrayBuffer
        );

        const res = new TextDecoder().decode(decrypted as ArrayBuffer);

        return res;
    } catch (err) {
        return '';
    }
}

function getKeyBytes(key: string): Uint8Array {
    const encoded = new TextEncoder().encode(key);
    const result = new Uint8Array(32);
    result.set(encoded.slice(0, 32));
    return result;
}

export async function deriveKey(e: string): Promise<string> {
    try {
        if (!e) return '';

        const base64ToBytes = (e: string) => {
            const t = atob(e.replace(/\s+/g, ''));
            const n = t.length;
            const r = new Uint8Array(n);
            for (let i = 0; i < n; i++) {
                r[i] = t.charCodeAt(i);
            }
            return r;
        };

        let t = base64ToBytes(e);
        if (t.length <= 28) return '';

        let n = t.slice(0, 12);
        let r = t.slice(12, 28);
        let a = t.slice(28);

        let i = new Uint8Array(a.length + r.length);
        i.set(a, 0);
        i.set(r, a.length);

        let encoder = new TextEncoder();
        let l = await crypto.subtle.digest(
            'SHA-256',
            encoder.encode('4f2a9c7d1e8b3a6f0d5c2e9a7b1f4d8c')
        );

        // l is an ArrayBuffer
        const importedKey = await crypto.subtle.importKey(
            'raw',
            l,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );

        // Prepare combined buffer as plain ArrayBuffer
        const combined = i;
        const combinedArrayBuffer = toPlainArrayBuffer(combined);

        const ivPlain = toPlainArrayBuffer(n);

        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: new Uint8Array(ivPlain),
                tagLength: 128
            },
            importedKey,
            combinedArrayBuffer
        );

        return new TextDecoder().decode(decrypted as ArrayBuffer);
    } catch (err) {
        return '';
    }
}
