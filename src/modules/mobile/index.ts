import { ml_kem512 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { randomBytes, webcrypto } from "crypto";

const { subtle } = webcrypto;

export interface MobileKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  algorithm: string;
  keyId: string;
}

export interface MobileEncapsulationResult {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
  algorithm: string;
}

export interface MobileSignatureResult {
  signature: Uint8Array;
  algorithm: string;
  keyId: string;
}

export class MobileModule {

  private generateKeyId(): string {
    return `AKR-MOB-${Date.now()}-${randomBytes(4).toString("hex").toUpperCase()}`;
  }

  generateKEMKeyPair(): MobileKeyPair {
    const seed = randomBytes(64);
    const keys = ml_kem512.keygen(seed);
    return {
      publicKey: keys.publicKey,
      privateKey: keys.secretKey,
      algorithm: "ML-KEM-512",
      keyId: this.generateKeyId(),
    };
  }

  generateSigningKeyPair(): MobileKeyPair {
    const seed = randomBytes(32);
    const keys = ml_dsa44.keygen(seed);
    return {
      publicKey: keys.publicKey,
      privateKey: keys.secretKey,
      algorithm: "ML-DSA-44",
      keyId: this.generateKeyId(),
    };
  }

  encapsulate(publicKey: Uint8Array): MobileEncapsulationResult {
    const result = ml_kem512.encapsulate(publicKey);
    return {
      ciphertext: result.cipherText,
      sharedSecret: result.sharedSecret,
      algorithm: "ML-KEM-512",
    };
  }

  decapsulate(
    ciphertext: Uint8Array,
    privateKey: Uint8Array
  ): Uint8Array {
    const key = new Uint8Array(Object.values(privateKey));
    return ml_kem512.decapsulate(ciphertext, key);
  }

  sign(
    message: Uint8Array,
    privateKey: Uint8Array,
    keyId: string
  ): MobileSignatureResult {
    const key = new Uint8Array(Object.values(privateKey));
    const msg = new Uint8Array(Object.values(message));
    const signature = ml_dsa44.sign(msg, key);
    return { signature, algorithm: "ML-DSA-44", keyId };
  }

  verify(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array
  ): boolean {
    const sig = new Uint8Array(Object.values(signature));
    const msg = new Uint8Array(Object.values(message));
    const pub = new Uint8Array(Object.values(publicKey));
    return ml_dsa44.verify(sig, msg, pub);
  }

  async encryptAES(
    data: Uint8Array,
    key: Uint8Array
  ): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
    const iv = randomBytes(12);
    const cryptoKey = await subtle.importKey(
      "raw",
      Buffer.from(key),
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );
    const encrypted = await subtle.encrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      Buffer.from(data)
    );
    return {
      ciphertext: new Uint8Array(encrypted),
      iv,
    };
  }

  async decryptAES(
    ciphertext: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array
  ): Promise<Uint8Array> {
    const cryptoKey = await subtle.importKey(
      "raw",
      Buffer.from(key),
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );
    const decrypted = await subtle.decrypt(
      { name: "AES-GCM", iv: Buffer.from(iv) },
      cryptoKey,
      Buffer.from(ciphertext)
    );
    return new Uint8Array(decrypted);
  }

  getProfile(): object {
    return {
      kemAlgorithm: "ML-KEM-512",
      signatureAlgorithm: "ML-DSA-44",
      kemPublicKeySize: 800,
      kemPrivateKeySize: 1632,
      kemCiphertextSize: 768,
      signaturePublicKeySize: 1312,
      signaturePrivateKeySize: 2560,
      signatureSize: 2420,
      optimizedFor: "mobile",
      securityLevel: "Category 1 — AES-128 equivalent",
    };
  }
}
