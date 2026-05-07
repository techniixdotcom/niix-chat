let _sodium = null;
window.sodiumReady = (async () => {
  for (let i = 0; i < 100 && !window.sodium; i++)
    await new Promise(r => setTimeout(r, 50));
  if (!window.sodium) throw new Error('libsodium failed to load (window.sodium not set)');
  await window.sodium.ready;
  _sodium = window.sodium;
})();
const PAD_BLOCK = 256;
function pad(plaintext) {
  const enc = new TextEncoder().encode(plaintext);
  const prefixed = new Uint8Array(4 + enc.length);
  new DataView(prefixed.buffer).setUint32(0, enc.length, true);
  prefixed.set(enc, 4);
  return _sodium.pad(prefixed, PAD_BLOCK);
}
function unpad(padded) {
  const raw = _sodium.unpad(padded, PAD_BLOCK);
  const len = new DataView(raw.buffer, raw.byteOffset, 4).getUint32(0, true);
  return new TextDecoder().decode(raw.slice(4, 4 + len));
}
const B64 = () => _sodium.base64_variants.URLSAFE_NO_PADDING;
const b64encode = (bytes) => _sodium.to_base64(bytes, B64());
const b64decode = (str)   => _sodium.from_base64(str, B64());
function deriveKeyFromPassword(password, salt) {
  return _sodium.crypto_pwhash(
    32,
    password,
    salt,
    _sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    _sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    _sodium.crypto_pwhash_ALG_ARGON2ID13
  );
}
function keypairFromSeed(seed) {
  const sign      = _sodium.crypto_sign_seed_keypair(seed);
  const kxPublic  = _sodium.crypto_sign_ed25519_pk_to_curve25519(sign.publicKey);
  const kxPrivate = _sodium.crypto_sign_ed25519_sk_to_curve25519(sign.privateKey);
  return { signPublicKey: sign.publicKey, signPrivateKey: sign.privateKey,
           kxPublicKey: kxPublic, kxPrivateKey: kxPrivate, seed };
}
function deriveSessionKey(myKeypair, peerKxPub) {
  const me = myKeypair.kxPublicKey, them = peerKxPub;
  let cmp = 0;
  for (let i = 0; i < 32 && cmp === 0; i++)
    cmp = me[i] < them[i] ? -1 : me[i] > them[i] ? 1 : 0;
  const ss = cmp <= 0
    ? _sodium.crypto_kx_client_session_keys(me, myKeypair.kxPrivateKey, them)
    : _sodium.crypto_kx_server_session_keys(me, myKeypair.kxPrivateKey, them);
  const key = new Uint8Array(32);
  for (let i = 0; i < 32; i++) key[i] = ss.sharedTx[i] ^ ss.sharedRx[i];
  return key;
}
function encryptMessage(plaintext, sessionKey) {
  const padded = pad(plaintext);
  const nonce  = _sodium.randombytes_buf(
    _sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ct = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    padded, null, null, nonce, sessionKey);
  const out = new Uint8Array(nonce.length + ct.length);
  out.set(nonce); out.set(ct, nonce.length);
  return b64encode(out);
}
function decryptMessage(b64ct, sessionKey) {
  const raw  = b64decode(b64ct);
  const NLEN = _sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  const padded = _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null, raw.slice(NLEN), null, raw.slice(0, NLEN), sessionKey);
  return unpad(padded);
}
function wrapFileKey(rawKey, sessionKey) {
  const nonce = _sodium.randombytes_buf(
    _sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ct  = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    rawKey, null, null, nonce, sessionKey);
  const out = new Uint8Array(nonce.length + ct.length);
  out.set(nonce); out.set(ct, nonce.length);
  return b64encode(out);
}
function unwrapFileKey(b64Wrapped, sessionKey) {
  const raw  = b64decode(b64Wrapped);
  const NLEN = _sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  return _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null, raw.slice(NLEN), null, raw.slice(0, NLEN), sessionKey);
}
const fpHex = async (pub) => {
  const hashBuf = await crypto.subtle.digest('SHA-256', pub instanceof Uint8Array ? pub : new Uint8Array(pub));
  return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
};
function encryptSeed(seed, password) {
  const salt  = _sodium.randombytes_buf(_sodium.crypto_pwhash_SALTBYTES);
  const key   = deriveKeyFromPassword(password, salt);
  const nonce = _sodium.randombytes_buf(_sodium.crypto_secretbox_NONCEBYTES);
  const ct    = _sodium.crypto_secretbox_easy(seed, nonce, key);
  const blob  = new Uint8Array(salt.length + nonce.length + ct.length);
  blob.set(salt); blob.set(nonce, salt.length);
  blob.set(ct, salt.length + nonce.length);
  return b64encode(blob);
}
function decryptSeed(blobB64, password) {
  const blob  = b64decode(blobB64);
  const SLEN  = _sodium.crypto_pwhash_SALTBYTES;
  const NLEN  = _sodium.crypto_secretbox_NONCEBYTES;
  const key   = deriveKeyFromPassword(password, blob.slice(0, SLEN));
  return _sodium.crypto_secretbox_open_easy(
    blob.slice(SLEN + NLEN), blob.slice(SLEN, SLEN + NLEN), key);
}
function packPublicKey(signPub, kxPub) {
  const p = new Uint8Array(64); p.set(signPub); p.set(kxPub, 32);
  return b64encode(p);
}
function unpackPublicKey(b64) {
  const raw = b64decode(b64);
  if (raw.length !== 64) throw new Error(`Bad public key: expected 64 bytes, got ${raw.length} (key starts: ${b64.slice(0,20)})`);
  return { signPublicKey: raw.slice(0, 32), kxPublicKey: raw.slice(32) };
}
async function encryptFile(fileBytes, rawKey) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const k   = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt']);
  const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, fileBytes);
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv); out.set(new Uint8Array(ct), 12);
  return out;
}
async function decryptFile(blob, rawKey) {
  const k  = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.slice(0, 12) }, k, blob.slice(12)));
}
function signData(data, signPrivateKey) {
  const msg = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return b64encode(_sodium.crypto_sign_detached(msg, signPrivateKey));
}
function verifySignature(data, sigB64, signPublicKey) {
  const msg = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return _sodium.crypto_sign_verify_detached(b64decode(sigB64), msg, signPublicKey);
}
const PGP = {
  async deriveKeypairFromCredentials(username, password) {
    // Derive a deterministic 32-byte seed from username+password using Argon2id.
    // Username is hashed to exactly crypto_pwhash_SALTBYTES (16) bytes as salt,
    // so two users with the same password get completely different keypairs.
    const saltRaw = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('niix:v1:' + username.toLowerCase()));
    const salt    = new Uint8Array(saltRaw).slice(0, _sodium.crypto_pwhash_SALTBYTES);
    const seed    = deriveKeyFromPassword(password, salt);
    return keypairFromSeed(seed);
  },
  async generateKeypair(username, password) {
    // Derive keypair deterministically — same credentials always produce the same keypair.
    // This allows login from any device without key transfer.
    const kp = await this.deriveKeypairFromCredentials(username, password);
    return {
      privateKey: encryptSeed(kp.seed, password),  // cached blob for fast local unlock
      publicKey:  packPublicKey(kp.signPublicKey, kp.kxPublicKey)
    };
  },
  async unlockPrivateKey(encryptedBlob, password) {
    const seed = decryptSeed(encryptedBlob, password);
    return keypairFromSeed(seed);
  },
  async readPublicKey(packedB64) {
    return unpackPublicKey(packedB64);
  },
  async encryptForEach(plaintext, recipients) {
    return recipients.map(r => ({
      recipientId: r.id,
      ciphertext:  encryptMessage(plaintext,
        deriveSessionKey(window._myKeypair, r.publicKeyObj.kxPublicKey))
    }));
  },
  async decrypt(ciphertext, privateKey, senderPublicKeyObj) {
    const sk = deriveSessionKey(privateKey, senderPublicKeyObj.kxPublicKey);
    return decryptMessage(ciphertext, sk);
  },
  async fingerprint(publicKeyObj) {
    const h = await fpHex(publicKeyObj.signPublicKey);
    return h.match(/.{1,4}/g).join(' ');
  },
  async shortId(publicKeyObj) {
    return (await fpHex(publicKeyObj.signPublicKey)).slice(-16).match(/.{1,4}/g).join(' ');
  },
  async rawFingerprint(publicKeyObj) {
    return await fpHex(publicKeyObj.signPublicKey);
  },
  async generateFileKey() { return _sodium.randombytes_buf(32); },
  async encryptFile(fileBytes, rawKey) { return encryptFile(fileBytes, rawKey); },
  async decryptFile(blobBytes, rawKey) { return decryptFile(blobBytes, rawKey); },
  async wrapKeyForEach(rawKey, recipients) {
    return recipients.map(r => ({
      recipientId: r.id,
      ciphertext:  wrapFileKey(rawKey,
        deriveSessionKey(window._myKeypair, r.publicKeyObj.kxPublicKey))
    }));
  },
  async unwrapKey(b64Wrapped, privateKey, senderPublicKeyObj) {
    return unwrapFileKey(b64Wrapped,
      deriveSessionKey(privateKey, senderPublicKeyObj.kxPublicKey));
  },
  signData,
  verifySignature,
  packPublicKey,
  unpackPublicKey
};
window.PGP = PGP;