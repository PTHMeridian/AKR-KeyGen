import { randomBytes } from "crypto";
import { ml_kem768, ml_kem512, ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { slh_dsa_sha2_128s } from "@noble/post-quantum/slh-dsa.js";
import type {
  KeyPair,
  KeyGenOptions,
  AKRConfig,
  AlgorithmName,
  EncapsulationResult,
  SignatureResult,
  VerificationResult,
} from "../types/index";

export class AKRKeyGen {
  private config: AKRConfig;

  constructor(config: AKRConfig) {
    this.config = config;
    this.log("AKR KeyGen engine initialized");
    this.log(`Default mode: ${config.defaultMode}`);
  }

  async generateKeyPair(options: KeyGenOptions): Promise<KeyPair> {
    const algorithm = options.algorithm ?? this.getDefaultAlgorithm(options.mode);
    const seedSize = this.getSeedSize(algorithm);
    const seed = randomBytes(seedSize);

    this.log(`Generating key pair — Algorithm: ${algorithm}`);

    let publicKey: Uint8Array;
    let privateKey: Uint8Array;

    switch (algorithm) {
      case "ML-KEM-768": {
        const keys = ml_kem768.keygen(seed);
        publicKey = keys.publicKey;
        privateKey = keys.secretKey;
        break;
      }
      case "ML-KEM-512": {
        const keys = ml_kem512.keygen(seed);
        publicKey = keys.publicKey;
        privateKey = keys.secretKey;
        break;
      }
      case "ML-KEM-1024": {
        const keys = ml_kem1024.keygen(seed);
        publicKey = keys.publicKey;
        privateKey = keys.secretKey;
        break;
      }
      case "ML-DSA-44": {
        const keys = ml_dsa44.keygen();
        publicKey = keys.publicKey;
        privateKey = keys.secretKey;
        break;
      }
      case "ML-DSA-65": {
        const keys = ml_dsa65.keygen();
        publicKey = keys.publicKey;
        privateKey = keys.secretKey;
        break;
      }
      case "ML-DSA-87": {
        const keys = ml_dsa87.keygen();
        publicKey = keys.publicKey;
        privateKey = keys.secretKey;
        break;
      }
      case "SLH-DSA-128s": {
        const keys = slh_dsa_sha2_128s.keygen();
        publicKey = keys.publicKey;
        privateKey = keys.secretKey;
        break;
      }
      default:
        throw new Error(`Algorithm ${algorithm} not yet implemented`);
    }

    const keyPair: KeyPair = {
      publicKey,
      privateKey,
      algorithm,
      mode: options.mode,
      createdAt: Date.now(),
      keyId: this.generateKeyId(),
    };

    this.log(`Key pair generated — ID: ${keyPair.keyId}`);
    return keyPair;
  }

  async encapsulate(
    publicKey: Uint8Array,
    algorithm: AlgorithmName
  ): Promise<EncapsulationResult> {
    this.log(`Encapsulating with ${algorithm}`);

    let ciphertext: Uint8Array;
    let sharedSecret: Uint8Array;

    switch (algorithm) {
      case "ML-KEM-768": {
        const result = ml_kem768.encapsulate(publicKey);
        ciphertext = result.cipherText;
        sharedSecret = result.sharedSecret;
        break;
      }
      case "ML-KEM-512": {
        const result = ml_kem512.encapsulate(publicKey);
        ciphertext = result.cipherText;
        sharedSecret = result.sharedSecret;
        break;
      }
      case "ML-KEM-1024": {
        const result = ml_kem1024.encapsulate(publicKey);
        ciphertext = result.cipherText;
        sharedSecret = result.sharedSecret;
        break;
      }
      default:
        throw new Error(`Encapsulation not supported for ${algorithm}`);
    }

    return { ciphertext, sharedSecret, algorithm };
  }

  async decapsulate(
    ciphertext: Uint8Array,
    privateKey: Uint8Array,
    algorithm: AlgorithmName
  ): Promise<Uint8Array> {
    this.log(`Decapsulating with ${algorithm}`);

    switch (algorithm) {
      case "ML-KEM-768":
        return ml_kem768.decapsulate(ciphertext, privateKey);
      case "ML-KEM-512":
        return ml_kem512.decapsulate(ciphertext, privateKey);
      case "ML-KEM-1024":
        return ml_kem1024.decapsulate(ciphertext, privateKey);
      default:
        throw new Error(`Decapsulation not supported for ${algorithm}`);
    }
  }

  async sign(
    message: Uint8Array,
    privateKey: Uint8Array,
    algorithm: AlgorithmName,
    keyId: string
  ): Promise<SignatureResult> {
    this.log(`Signing with ${algorithm}`);
  
    // Force proper Uint8Array — plain objects with numeric indices fail noble's type check
    const key = new Uint8Array(Object.values(privateKey));
    const msg = new Uint8Array(Object.values(message));
  
    let signature: Uint8Array;
    switch (algorithm) {
        case "ML-DSA-44":
          signature = ml_dsa44.sign(msg, key);
          break;
        case "ML-DSA-65":
          signature = ml_dsa65.sign(msg, key);
          break;
        case "ML-DSA-87":
          signature = ml_dsa87.sign(msg, key);
          break;
        case "SLH-DSA-128s":
          signature = slh_dsa_sha2_128s.sign(msg, key);
          break;
        default:
          throw new Error(`Signing not supported for ${algorithm}`);
      }

    return { signature, algorithm, keyId };
  }

  async verify(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
    algorithm: AlgorithmName,
    keyId: string
  ): Promise<VerificationResult> {
    this.log(`Verifying with ${algorithm}`);
  
    const pub = new Uint8Array(Object.values(publicKey));
    const msg = new Uint8Array(Object.values(message));
    const sig = new Uint8Array(Object.values(signature));
  
    let valid: boolean;
  
    switch (algorithm) {
      case "ML-DSA-44":
        valid = ml_dsa44.verify(sig, msg, pub);
        break;
      case "ML-DSA-65":
        valid = ml_dsa65.verify(sig, msg, pub);
        break;
      case "ML-DSA-87":
        valid = ml_dsa87.verify(sig, msg, pub);
        break;
      case "SLH-DSA-128s":
        valid = slh_dsa_sha2_128s.verify(sig, msg, pub);
        break;
      default:
        throw new Error(`Verification not supported for ${algorithm}`);
    }
  
    return { valid, algorithm, keyId };
  }

  private getDefaultAlgorithm(mode: string): AlgorithmName {
    switch (mode) {
      case "quantum":
        return "ML-KEM-768";
      case "mobile":
        return "ML-KEM-512";
      case "classic":
        return "ECDSA-P256";
      case "hybrid":
        return "HYBRID-ECDH-MLKEM";
      default:
        return "ML-KEM-768";
    }
  }

  private getSeedSize(algorithm: AlgorithmName): number {
    switch (algorithm) {
      case "ML-KEM-512":
      case "ML-KEM-768":
      case "ML-KEM-1024":
        return 64;
      case "ML-DSA-44":
      case "ML-DSA-65":
      case "ML-DSA-87":
        return 32;
      case "SLH-DSA-128s":
        return 48;
      default:
        return 32;
    }
  }
  private generateKeyId(): string {
    return `AKR-${Date.now()}-${randomBytes(4).toString("hex").toUpperCase()}`;
  }

  private log(message: string): void {
    if (this.config.enableAuditLog) {
      const timestamp = new Date().toISOString();
      console.log(`[${timestamp}] [AKR] ${message}`);
    }
  }
}