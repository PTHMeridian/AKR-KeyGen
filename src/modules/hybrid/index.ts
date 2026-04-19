import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { randomBytes, webcrypto } from "crypto";

const { subtle } = webcrypto;

export interface HybridKeyPair {
  classical: {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  };
  quantum: {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  };
  algorithm: string;
}

export interface HybridEncapsulationResult {
  classicalCiphertext: Uint8Array;
  quantumCiphertext: Uint8Array;
  sharedSecret: Uint8Array;
  algorithm: string;
}

export interface HybridSignatureResult {
  classicalSignature: Uint8Array;
  quantumSignature: Uint8Array;
  algorithm: string;
  keyId: string;
}

export class HybridModule {

  generateKeyPair(): HybridKeyPair {
    const classicalPrivateKey = p256.utils.randomSecretKey();
    const classicalPublicKey = p256.getPublicKey(classicalPrivateKey);

    const quantumSeed = randomBytes(64);
    const quantumKeys = ml_kem768.keygen(quantumSeed);

    return {
      classical: {
        publicKey: classicalPublicKey,
        privateKey: classicalPrivateKey,
      },
      quantum: {
        publicKey: quantumKeys.publicKey,
        privateKey: quantumKeys.secretKey,
      },
      algorithm: "HYBRID-ECDH-MLKEM768",
    };
  }

  generateSigningKeyPair(): HybridKeyPair {
    const classicalPrivateKey = p256.utils.randomSecretKey();
    const classicalPublicKey = p256.getPublicKey(classicalPrivateKey);

    const quantumSeed = randomBytes(32);
    const quantumKeys = ml_dsa65.keygen(quantumSeed);

    return {
      classical: {
        publicKey: classicalPublicKey,
        privateKey: classicalPrivateKey,
      },
      quantum: {
        publicKey: quantumKeys.publicKey,
        privateKey: quantumKeys.secretKey,
      },
      algorithm: "HYBRID-ECDSA-MLDSA65",
    };
  }

  encapsulate(
    classicalPublicKey: Uint8Array,
    quantumPublicKey: Uint8Array
  ): HybridEncapsulationResult {
    const ephemeralPrivateKey = p256.utils.randomSecretKey();
    const ephemeralPublicKey = p256.getPublicKey(ephemeralPrivateKey);
    const classicalSharedSecret = p256.getSharedSecret(
      ephemeralPrivateKey,
      classicalPublicKey
    );

    const quantumResult = ml_kem768.encapsulate(quantumPublicKey);

    const combined = new Uint8Array(
      classicalSharedSecret.length + quantumResult.sharedSecret.length
    );
    combined.set(classicalSharedSecret);
    combined.set(quantumResult.sharedSecret, classicalSharedSecret.length);

    const sharedSecret = hkdf(
      sha256,
      combined,
      undefined,
      new TextEncoder().encode("AKR-HYBRID-v1"),
      32
    );

    return {
      classicalCiphertext: ephemeralPublicKey,
      quantumCiphertext: quantumResult.cipherText,
      sharedSecret,
      algorithm: "HYBRID-ECDH-MLKEM768",
    };
  }

  decapsulate(
    classicalCiphertext: Uint8Array,
    quantumCiphertext: Uint8Array,
    classicalPrivateKey: Uint8Array,
    quantumPrivateKey: Uint8Array
  ): Uint8Array {
    const classicalSharedSecret = p256.getSharedSecret(
      classicalPrivateKey,
      classicalCiphertext
    );

    const quantumSharedSecret = ml_kem768.decapsulate(
      quantumCiphertext,
      new Uint8Array(Object.values(quantumPrivateKey))
    );

    const combined = new Uint8Array(
      classicalSharedSecret.length + quantumSharedSecret.length
    );
    combined.set(classicalSharedSecret);
    combined.set(quantumSharedSecret, classicalSharedSecret.length);

    return hkdf(
      sha256,
      combined,
      undefined,
      new TextEncoder().encode("AKR-HYBRID-v1"),
      32
    );
  }

  sign(
    message: Uint8Array,
    classicalPrivateKey: Uint8Array,
    quantumPrivateKey: Uint8Array,
    keyId: string
  ): HybridSignatureResult {
    const hash = sha256(message);
    const classicalSignature = p256.sign(
      hash,
      classicalPrivateKey
    ) as unknown as Uint8Array;

    const quantumKey = new Uint8Array(Object.values(quantumPrivateKey));
    const quantumSignature = ml_dsa65.sign(message, quantumKey);

    return {
      classicalSignature,
      quantumSignature,
      algorithm: "HYBRID-ECDSA-MLDSA65",
      keyId,
    };
  }

  verify(
    message: Uint8Array,
    classicalSignature: Uint8Array,
    quantumSignature: Uint8Array,
    classicalPublicKey: Uint8Array,
    quantumPublicKey: Uint8Array
  ): { classicalValid: boolean; quantumValid: boolean; bothValid: boolean } {
    const hash = sha256(message);

    const classicalValid = p256.verify(
      classicalSignature,
      hash,
      classicalPublicKey
    );

    const quantumSig = new Uint8Array(Object.values(quantumSignature));
    const quantumMsg = new Uint8Array(Object.values(message));
    const quantumPub = new Uint8Array(Object.values(quantumPublicKey));
    const quantumValid = ml_dsa65.verify(quantumSig, quantumMsg, quantumPub);

    return {
      classicalValid,
      quantumValid,
      bothValid: classicalValid && quantumValid,
    };
  }

  async encryptWithSharedSecret(
    data: Uint8Array,
    sharedSecret: Uint8Array
  ): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
    const iv = randomBytes(12);
    const cryptoKey = await subtle.importKey(
      "raw",
      Buffer.from(sharedSecret),
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

  async decryptWithSharedSecret(
    ciphertext: Uint8Array,
    sharedSecret: Uint8Array,
    iv: Uint8Array
  ): Promise<Uint8Array> {
    const cryptoKey = await subtle.importKey(
      "raw",
      Buffer.from(sharedSecret),
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
}
