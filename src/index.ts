import { AKRKeyGen } from "./core/AKRKeyGen";
import type { KeyGenOptions } from "./types/index";

async function main() {
  console.log("AKR KeyGen - SA AT Cryptographics");
  console.log("Initializing cryptographic engine...\n");

  const akr = new AKRKeyGen({
    defaultMode: "quantum",
    enableAuditLog: true,
    keyPoolSize: 10,
    rotationIntervalDays: 90,
  });

  const options: KeyGenOptions = {
    mode: "quantum",
    algorithm: "ML-KEM-768",
  };

  console.log("Generating ML-KEM-768 key pair...");
  const keyPair = await akr.generateKeyPair(options);

  console.log(`\nKey ID:              ${keyPair.keyId}`);
  console.log(`Algorithm:           ${keyPair.algorithm}`);
  console.log(`Mode:                ${keyPair.mode}`);
  console.log(`Public Key Length:   ${keyPair.publicKey.length} bytes`);
  console.log(`Private Key Length:  ${keyPair.privateKey.length} bytes`);
  console.log(`Created:             ${new Date(keyPair.createdAt).toISOString()}`);

  console.log("\n--- Testing Encapsulation ---");
  const encResult = await akr.encapsulate(keyPair.publicKey, "ML-KEM-768");
  console.log(`Ciphertext Length:   ${encResult.ciphertext.length} bytes`);
  console.log(`Shared Secret:       ${encResult.sharedSecret.length} bytes`);

  console.log("\n--- Testing Signing with ML-DSA-65 ---");
  const sigKeys = await akr.generateKeyPair({
    mode: "quantum",
    algorithm: "ML-DSA-65",
  });

  const message = new TextEncoder().encode("PTH Meridian - Ask. Solve. Done.");

  const sigResult = await akr.sign(
    message,
    sigKeys.privateKey,
    "ML-DSA-65",
    sigKeys.keyId
  );
  console.log(`Signature Length:    ${sigResult.signature.length} bytes`);

  const verResult = await akr.verify(
    message,
    sigResult.signature,
    sigKeys.publicKey,
    "ML-DSA-65",
    sigKeys.keyId
  );
  console.log(`Signature Valid:     ${verResult.valid}`);

  console.log("\n--- Testing Classical Module ---");
  const { ClassicalModule } = await import("./modules/classical/index");
  const classical = new ClassicalModule();

  const ecdsaKeys = classical.generateECDSAKeyPair("P-256");
  console.log(`ECDSA P-256 Public Key:  ${ecdsaKeys.publicKey.length} bytes`);
  console.log(`ECDSA P-256 Private Key: ${ecdsaKeys.privateKey.length} bytes`);

  const classicalSig = classical.signECDSA(message, ecdsaKeys.privateKey, "P-256");
  console.log(`ECDSA Signature Length:  ${classicalSig.length} bytes`);

  const classicalValid = classical.verifyECDSA(message, classicalSig, ecdsaKeys.publicKey, "P-256");
  console.log(`ECDSA Signature Valid:   ${classicalValid}`);

  const aesKey = classical.generateAESKey(256);
  console.log(`AES-256 Key Length:      ${aesKey.key.length} bytes`);

  const encrypted = await classical.encryptAES(message, aesKey.key);
  console.log(`AES Ciphertext Length:   ${encrypted.ciphertext.length} bytes`);

  const decrypted = await classical.decryptAES(encrypted.ciphertext, aesKey.key, encrypted.iv);
  console.log(`AES Decrypted Match:     ${new TextDecoder().decode(decrypted) === new TextDecoder().decode(message)}`);

  console.log("\n--- Testing Hybrid Module ---");
  const { HybridModule } = await import("./modules/hybrid/index");
  const hybrid = new HybridModule();

  const hybridKEMKeys = hybrid.generateKeyPair();
  console.log(`Hybrid KEM Classical Public Key:  ${hybridKEMKeys.classical.publicKey.length} bytes`);
  console.log(`Hybrid KEM Quantum Public Key:    ${hybridKEMKeys.quantum.publicKey.length} bytes`);

  const encap = hybrid.encapsulate(
    hybridKEMKeys.classical.publicKey,
    hybridKEMKeys.quantum.publicKey
  );
  console.log(`Classical Ciphertext:  ${encap.classicalCiphertext.length} bytes`);
  console.log(`Quantum Ciphertext:    ${encap.quantumCiphertext.length} bytes`);
  console.log(`Shared Secret:         ${encap.sharedSecret.length} bytes`);

  const decapSecret = hybrid.decapsulate(
    encap.classicalCiphertext,
    encap.quantumCiphertext,
    hybridKEMKeys.classical.privateKey,
    hybridKEMKeys.quantum.privateKey
  );
  console.log(`Decapsulation Match:   ${Buffer.from(decapSecret).toString("hex") === Buffer.from(encap.sharedSecret).toString("hex")}`);

  const hybridSigKeys = hybrid.generateSigningKeyPair();
  const hybridSig = hybrid.sign(
    message,
    hybridSigKeys.classical.privateKey,
    hybridSigKeys.quantum.privateKey,
    "HYBRID-TEST-KEY"
  );
  console.log(`Classical Signature:   ${hybridSig.classicalSignature.length} bytes`);
  console.log(`Quantum Signature:     ${hybridSig.quantumSignature.length} bytes`);

  const hybridVerify = hybrid.verify(
    message,
    hybridSig.classicalSignature,
    hybridSig.quantumSignature,
    hybridSigKeys.classical.publicKey,
    hybridSigKeys.quantum.publicKey
  );
  console.log(`Classical Valid:       ${hybridVerify.classicalValid}`);
  console.log(`Quantum Valid:         ${hybridVerify.quantumValid}`);
  console.log(`Both Valid:            ${hybridVerify.bothValid}`);

  console.log("\n--- Testing Mobile Module ---");
  const { MobileModule } = await import("./modules/mobile/index");
  const mobile = new MobileModule();

  const mobileKEMKeys = mobile.generateKEMKeyPair();
  console.log(`ML-KEM-512 Public Key:  ${mobileKEMKeys.publicKey.length} bytes`);
  console.log(`ML-KEM-512 Private Key: ${mobileKEMKeys.privateKey.length} bytes`);

  const mobileEncap = mobile.encapsulate(mobileKEMKeys.publicKey);
  console.log(`Ciphertext:             ${mobileEncap.ciphertext.length} bytes`);
  console.log(`Shared Secret:          ${mobileEncap.sharedSecret.length} bytes`);

  const mobileDecap = mobile.decapsulate(
    mobileEncap.ciphertext,
    mobileKEMKeys.privateKey
  );
  console.log(`Decapsulation Match:    ${Buffer.from(mobileDecap).toString("hex") === Buffer.from(mobileEncap.sharedSecret).toString("hex")}`);

  const mobileSigKeys = mobile.generateSigningKeyPair();
  const mobileSig = mobile.sign(message, mobileSigKeys.privateKey, mobileSigKeys.keyId);
  console.log(`ML-DSA-44 Signature:    ${mobileSig.signature.length} bytes`);

  const mobileValid = mobile.verify(message, mobileSig.signature, mobileSigKeys.publicKey);
  console.log(`Signature Valid:        ${mobileValid}`);

  const mobileEncrypted = await mobile.encryptAES(message, mobileEncap.sharedSecret);
  console.log(`AES Ciphertext:         ${mobileEncrypted.ciphertext.length} bytes`);

  const mobileDecrypted = await mobile.decryptAES(
    mobileEncrypted.ciphertext,
    mobileEncap.sharedSecret,
    mobileEncrypted.iv
  );
  console.log(`AES Decrypted Match:    ${new TextDecoder().decode(mobileDecrypted) === new TextDecoder().decode(message)}`);

  console.log("\nAll tests completed successfully.");
}

main().catch(console.error);
