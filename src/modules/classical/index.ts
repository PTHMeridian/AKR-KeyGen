import { p256, p384 } from "@noble/curves/nist.js";
import { sha256, sha384 } from "@noble/hashes/sha2.js";
import { randomBytes, webcrypto } from "crypto";

const { subtle } = webcrypto;

export interface ClassicalKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  algorithm: string;
}

export interface AESKey {
  key: Uint8Array;
  algorithm: string;
}

export class ClassicalModule {

  generateECDSAKeyPair(curve: "P-256" | "P-384" = "P-256"): ClassicalKeyPair {
    if (curve === "P-256") {
      const privateKey = p256.utils.randomSecretKey();
      const publicKey = p256.getPublicKey(privateKey);
      return { privateKey, publicKey, algorithm: "ECDSA-P256" };
    } else {
      const privateKey = p384.utils.randomSecretKey();
      const publicKey = p384.getPublicKey(privateKey);
      return { privateKey, publicKey, algorithm: "ECDSA-P384" };
    }
  }

  generateAESKey(bits: 128 | 256 = 256): AESKey {
    const key = randomBytes(bits / 8);
    return { key, algorithm: `AES-${bits}` };
  }

  signECDSA(
    message: Uint8Array,
    privateKey: Uint8Array,
    curve: "P-256" | "P-384" = "P-256"
  ): Uint8Array {
    const hash = curve === "P-256" ? sha256(message) : sha384(message);
    if (curve === "P-256") {
      return p256.sign(hash, privateKey) as unknown as Uint8Array;
    } else {
      return p384.sign(hash, privateKey) as unknown as Uint8Array;
    }
  }

  verifyECDSA(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
    curve: "P-256" | "P-384" = "P-256"
  ): boolean {
    const hash = curve === "P-256" ? sha256(message) : sha384(message);
    if (curve === "P-256") {
      return p256.verify(signature, hash, publicKey);
    } else {
      return p384.verify(signature, hash, publicKey);
    }
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
      { name: "AES-GCM", iv: new Uint8Array(iv) },
      cryptoKey,
      Buffer.from(ciphertext)
    );
    return new Uint8Array(decrypted);
  }
}
