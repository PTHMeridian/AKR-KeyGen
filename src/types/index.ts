export type KeyMode = "classic" | "quantum" | "hybrid" | "mobile";

export type AlgorithmName =
  | "RSA-4096"
  | "ECDSA-P256"
  | "ECDSA-P384"
  | "AES-256"
  | "ML-KEM-512"
  | "ML-KEM-768"
  | "ML-KEM-1024"
  | "ML-DSA-44"
  | "ML-DSA-65"
  | "ML-DSA-87"
  | "SLH-DSA-128s"
  | "HYBRID-ECDH-MLKEM"
  | "HYBRID-ECDSA-MLDSA";

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  algorithm: AlgorithmName;
  mode: KeyMode;
  createdAt: number;
  keyId: string;
}

export interface EncapsulationResult {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
  algorithm: AlgorithmName;
}

export interface SignatureResult {
  signature: Uint8Array;
  algorithm: AlgorithmName;
  keyId: string;
}

export interface VerificationResult {
  valid: boolean;
  algorithm: AlgorithmName;
  keyId: string;
}

export interface KeyGenOptions {
  mode: KeyMode;
  algorithm?: AlgorithmName;
  metadata?: Record<string, string>;
}

export interface AKRConfig {
  defaultMode: KeyMode;
  enableAuditLog: boolean;
  keyPoolSize: number;
  rotationIntervalDays: number;
}