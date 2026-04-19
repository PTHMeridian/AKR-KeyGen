import { AKRKeyGen } from "./core/AKRKeyGen";
import type { KeyGenOptions } from "./types/index";

async function main() {
  console.log("AKR KeyGen — SA'AT Cryptographics");
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

  const message = new TextEncoder().encode("PTH Meridian — Ask. Solve. Done.");

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

  const classicalSig = classical.signECDSA(
    message,
    ecdsaKeys.privateKey,
    "P-256"
  );
  console.log(`ECDSA Signature Length:  ${classicalSig.length} bytes`);

  const classicalValid = classical.verifyECDSA(
    message,
    classicalSig,
    ecdsaKeys.publicKey,
    "P-256"
  );
  console.log(`ECDSA Signature Valid:   ${classicalValid}`);

  const aesKey = classical.generateAESKey(256);
  console.log(`AES-256 Key Length:      ${aesKey.key.length} bytes`);

  const encrypted = await classical.encryptAES(message, aesKey.key);
  console.log(`AES Ciphertext Length:   ${encrypted.ciphertext.length} bytes`);

  const decrypted = await classical.decryptAES(
    encrypted.ciphertext,
    aesKey.key,
    encrypted.iv
  );

  const decryptedText = new TextDecoder().decode(decrypted);
  const originalText = new TextDecoder().decode(message);
  console.log(`AES Decrypted Match:     ${decryptedText === originalText}`);

  console.log("\nAll tests completed successfully.");
}

main().catch(console.error);