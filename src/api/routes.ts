import express from "express";
import { AKRKeyGen } from "../core/AKRKeyGen";
import { ClassicalModule } from "../modules/classical/index";
import { HybridModule } from "../modules/hybrid/index";
import { MobileModule } from "../modules/mobile/index";

const router = express.Router();
const akr = new AKRKeyGen({
  defaultMode: "quantum",
  enableAuditLog: true,
  keyPoolSize: 10,
  rotationIntervalDays: 90,
});
const classical = new ClassicalModule();
const hybrid = new HybridModule();
const mobile = new MobileModule();

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function fromBase64(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, "base64"));
}

router.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    service: "AKR KeyGen",
    version: "1.0.0",
    modules: ["quantum", "classical", "hybrid", "mobile"],
    timestamp: new Date().toISOString(),
  });
});

router.post("/generate", async (req, res) => {
  try {
    const { mode = "quantum", algorithm } = req.body;
    const keyPair = await akr.generateKeyPair({ mode, algorithm });
    res.json({
      keyId: keyPair.keyId,
      algorithm: keyPair.algorithm,
      mode: keyPair.mode,
      publicKey: toBase64(keyPair.publicKey),
      privateKey: toBase64(keyPair.privateKey),
      createdAt: keyPair.createdAt,
    });
  } catch (err: unknown) {
    res.status(400).json({ error: err instanceof Error ? err.message : "Unknown error" });
  }
});

router.post("/encapsulate", async (req, res) => {
  try {
    const { publicKey, algorithm = "ML-KEM-768" } = req.body;
    const result = await akr.encapsulate(fromBase64(publicKey), algorithm);
    res.json({
      ciphertext: toBase64(result.ciphertext),
      sharedSecret: toBase64(result.sharedSecret),
      algorithm: result.algorithm,
    });
  } catch (err: unknown) {
    res.status(400).json({ error: err instanceof Error ? err.message : "Unknown error" });
  }
});

router.post("/sign", async (req, res) => {
  try {
    const { message, privateKey, algorithm = "ML-DSA-65", keyId } = req.body;
    const msg = new TextEncoder().encode(message);
    const result = await akr.sign(msg, fromBase64(privateKey), algorithm, keyId);
    res.json({
      signature: toBase64(result.signature),
      algorithm: result.algorithm,
      keyId: result.keyId,
    });
  } catch (err: unknown) {
    res.status(400).json({ error: err instanceof Error ? err.message : "Unknown error" });
  }
});

router.post("/verify", async (req, res) => {
  try {
    const { message, signature, publicKey, algorithm = "ML-DSA-65", keyId } = req.body;
    const msg = new TextEncoder().encode(message);
    const result = await akr.verify(
      msg,
      fromBase64(signature),
      fromBase64(publicKey),
      algorithm,
      keyId
    );
    res.json({
      valid: result.valid,
      algorithm: result.algorithm,
      keyId: result.keyId,
    });
  } catch (err: unknown) {
    res.status(400).json({ error: err instanceof Error ? err.message : "Unknown error" });
  }
});

router.post("/classical/generate", (_req, res) => {
  try {
    const { curve = "P-256" } = _req.body;
    const keyPair = classical.generateECDSAKeyPair(curve);
    res.json({
      publicKey: toBase64(keyPair.publicKey),
      privateKey: toBase64(keyPair.privateKey),
      algorithm: keyPair.algorithm,
    });
  } catch (err: unknown) {
    res.status(400).json({ error: err instanceof Error ? err.message : "Unknown error" });
  }
});

router.post("/hybrid/generate", (_req, res) => {
  try {
    const keyPair = hybrid.generateKeyPair();
    res.json({
      classical: {
        publicKey: toBase64(keyPair.classical.publicKey),
        privateKey: toBase64(keyPair.classical.privateKey),
      },
      quantum: {
        publicKey: toBase64(keyPair.quantum.publicKey),
        privateKey: toBase64(keyPair.quantum.privateKey),
      },
      algorithm: keyPair.algorithm,
    });
  } catch (err: unknown) {
    res.status(400).json({ error: err instanceof Error ? err.message : "Unknown error" });
  }
});

router.post("/mobile/generate", (_req, res) => {
  try {
    const kemKeys = mobile.generateKEMKeyPair();
    const sigKeys = mobile.generateSigningKeyPair();
    res.json({
      kem: {
        publicKey: toBase64(kemKeys.publicKey),
        privateKey: toBase64(kemKeys.privateKey),
        algorithm: kemKeys.algorithm,
        keyId: kemKeys.keyId,
      },
      signing: {
        publicKey: toBase64(sigKeys.publicKey),
        privateKey: toBase64(sigKeys.privateKey),
        algorithm: sigKeys.algorithm,
        keyId: sigKeys.keyId,
      },
    });
  } catch (err: unknown) {
    res.status(400).json({ error: err instanceof Error ? err.message : "Unknown error" });
  }
});

router.get("/mobile/profile", (_req, res) => {
  res.json(mobile.getProfile());
});

export default router;
