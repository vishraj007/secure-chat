/* ============================================================================
   Secure Chat Lab — Crypto Core (Pure JavaScript)
   ============================================================================
   Implements:
     • Diffie-Hellman key exchange (simulated with Web Crypto ECDH for real security)
     • HKDF-SHA256 key derivation → AES key + HMAC key
     • AES-256-CBC encryption with PKCS7 padding and random IV
     • HMAC-SHA256 integrity (encrypt-then-MAC with sequence numbers)
     • Tamper, replay, and MITM attack simulations
   -------------------------------------------------------------------------- */

// ============================================================================
// Big-integer DH simulation for educational display
// (We use Web Crypto ECDH internally for real key agreement, but display
//  RFC 3526 parameters so the student can see the math.)
// ============================================================================

const P_HEX =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
  "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
  "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
  "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
  "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
  "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

function shortHex(hex, width = 24) {
  if (hex.length <= width * 2) return hex;
  return hex.slice(0, width) + " … " + hex.slice(-width);
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

// ============================================================================
// Key Derivation (HKDF-SHA256 via Web Crypto)
// ============================================================================

class Keys {
  constructor(aesKey, macKey, aesKeyRaw, macKeyRaw) {
    this.aesKey = aesKey;         // CryptoKey for AES-CBC
    this.macKey = macKey;         // CryptoKey for HMAC
    this.aesKeyRaw = aesKeyRaw;  // Raw bytes (for display)
    this.macKeyRaw = macKeyRaw;  // Raw bytes (for display)
    this.sendSeq = 0;
    this.recvSeq = 0;
  }
}

async function deriveKeys(sharedSecretBytes) {
  // Import the shared secret as raw key material
  const ikm = await crypto.subtle.importKey(
    "raw", sharedSecretBytes, "HKDF", false, ["deriveBits"]
  );

  // Derive 64 bytes: first 32 for AES, last 32 for HMAC
  const okm = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),       // zero salt
      info: new TextEncoder().encode("secure-chat-lab"),
    },
    ikm,
    512  // 64 bytes = 512 bits
  );

  const okmBytes = new Uint8Array(okm);
  const aesRaw = okmBytes.slice(0, 32);
  const macRaw = okmBytes.slice(32, 64);

  const aesKey = await crypto.subtle.importKey(
    "raw", aesRaw, { name: "AES-CBC" }, false, ["encrypt", "decrypt"]
  );
  const macKey = await crypto.subtle.importKey(
    "raw", macRaw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]
  );

  return new Keys(aesKey, macKey, aesRaw, macRaw);
}

// ============================================================================
// AES-256-CBC Encryption with PKCS7 Padding
// ============================================================================

function pkcs7Pad(data, blockSize = 16) {
  const padLen = blockSize - (data.length % blockSize);
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data);
  padded.fill(padLen, data.length);
  return padded;
}

function pkcs7Unpad(data) {
  const padLen = data[data.length - 1];
  if (padLen < 1 || padLen > 16) throw new Error("Invalid PKCS7 padding");
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) throw new Error("Invalid PKCS7 padding");
  }
  return data.slice(0, data.length - padLen);
}

// ============================================================================
// Encrypt Message → packet = seq(8) | iv(16) | ciphertext | hmac(32)
// ============================================================================

async function encryptMessage(keys, text) {
  keys.sendSeq++;
  const seq = new Uint8Array(8);
  new DataView(seq.buffer).setBigUint64(0, BigInt(keys.sendSeq));

  const iv = randomBytes(16);
  const plainBytes = new TextEncoder().encode(text);
  const padded = pkcs7Pad(plainBytes);

  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-CBC", iv: iv },
    keys.aesKey,
    padded
  ));

  // HMAC over seq + iv + ct
  const macInput = new Uint8Array(seq.length + iv.length + ct.length);
  macInput.set(seq, 0);
  macInput.set(iv, seq.length);
  macInput.set(ct, seq.length + iv.length);

  const tag = new Uint8Array(await crypto.subtle.sign("HMAC", keys.macKey, macInput));

  // Assemble packet
  const packet = new Uint8Array(seq.length + iv.length + ct.length + tag.length);
  packet.set(seq, 0);
  packet.set(iv, 8);
  packet.set(ct, 24);
  packet.set(tag, packet.length - 32);

  return packet;
}

// ============================================================================
// Decrypt Message (verify HMAC first, then replay check, then decrypt)
// ============================================================================

async function decryptMessage(keys, packet, checkReplay = true) {
  if (packet.length < 8 + 16 + 16 + 32) {
    throw new Error("Packet too short");
  }

  const seq  = packet.slice(0, 8);
  const iv   = packet.slice(8, 24);
  const ct   = packet.slice(24, packet.length - 32);
  const tag  = packet.slice(packet.length - 32);

  // Verify HMAC
  const macInput = new Uint8Array(seq.length + iv.length + ct.length);
  macInput.set(seq, 0);
  macInput.set(iv, seq.length);
  macInput.set(ct, seq.length + iv.length);

  const valid = await crypto.subtle.verify("HMAC", keys.macKey, tag, macInput);
  if (!valid) {
    throw new Error("HMAC verification FAILED — message was modified");
  }

  // Replay check
  const seqNum = Number(new DataView(seq.buffer, seq.byteOffset).getBigUint64(0));
  if (checkReplay && seqNum <= keys.recvSeq) {
    throw new Error(`REPLAY detected — sequence ${seqNum} already seen`);
  }

  // Decrypt
  const padded = new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-CBC", iv: iv },
    keys.aesKey,
    ct
  ));

  const plain = pkcs7Unpad(padded);
  if (checkReplay) {
    keys.recvSeq = seqNum;
  }

  return new TextDecoder().decode(plain);
}

// ============================================================================
// Party — one side of the conversation
// Uses ECDH (P-256) under the hood for real key agreement,
// but generates display-only "DH values" for educational purposes.
// ============================================================================

class Party {
  constructor(name) {
    this.name = name;
    this.keys = null;

    // For display purposes: simulate big DH numbers
    this._secretDisplay = bytesToHex(randomBytes(64));   // "private key x"
    this._publicDisplay = bytesToHex(randomBytes(128));  // "public value g^x mod p"

    // Real ECDH keys (set asynchronously)
    this._ecdhKeyPair = null;
    this._rawPublicKey = null;
  }

  async generateKeys() {
    this._ecdhKeyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
    this._rawPublicKey = await crypto.subtle.exportKey("raw", this._ecdhKeyPair.publicKey);
  }

  async computeShared(peerPublicKeyRaw) {
    const peerPublicKey = await crypto.subtle.importKey(
      "raw",
      peerPublicKeyRaw,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );

    const sharedBits = await crypto.subtle.deriveBits(
      { name: "ECDH", public: peerPublicKey },
      this._ecdhKeyPair.privateKey,
      256
    );

    const sharedSecret = new Uint8Array(sharedBits);
    this.keys = await deriveKeys(sharedSecret);
    return sharedSecret;
  }

  get secretHex() { return this._secretDisplay; }
  get publicHex() { return this._publicDisplay; }
  get rawPublicKey() { return this._rawPublicKey; }
}

// ============================================================================
// Packet utilities
// ============================================================================

function parsePacket(packet) {
  return {
    seq: Number(new DataView(packet.buffer, packet.byteOffset).getBigUint64(0)),
    iv:  bytesToHex(packet.slice(8, 24)),
    ct:  bytesToHex(packet.slice(24, packet.length - 32)),
    tag: bytesToHex(packet.slice(packet.length - 32)),
  };
}

function tamperPacket(packet) {
  const tampered = new Uint8Array(packet);
  if (tampered.length > 26) {
    tampered[26] ^= 0x01;  // flip one bit in the ciphertext
  }
  return tampered;
}
