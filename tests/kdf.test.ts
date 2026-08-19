import { describe, expect, it } from "vitest";
import { deriveKey, generateSalt } from "../src/core/kdf.js";
import {
  InvalidParameterError,
  WeakMasterPasswordError,
} from "../src/core/errors.js";

const MASTER_PASSWORD = "güçlü-bir-master-parola";
const FAST_ITERATIONS = 100_000;

describe("PBKDF2 anahtar türetme", () => {
  it("aynı girdilerle aynı anahtarı türetmeli (deterministik)", async () => {
    const salt = generateSalt();
    const a = await deriveKey(MASTER_PASSWORD, salt, FAST_ITERATIONS);
    const b = await deriveKey(MASTER_PASSWORD, salt, FAST_ITERATIONS);
    expect(Buffer.from(a)).toEqual(Buffer.from(b));
  });

  it("32 baytlık anahtar üretmeli", async () => {
    const key = await deriveKey(
      MASTER_PASSWORD,
      generateSalt(),
      FAST_ITERATIONS,
    );
    expect(key.length).toBe(32);
  });

  it("farklı tuzlarla farklı anahtarlar üretmeli", async () => {
    const a = await deriveKey(MASTER_PASSWORD, generateSalt(), FAST_ITERATIONS);
    const b = await deriveKey(MASTER_PASSWORD, generateSalt(), FAST_ITERATIONS);
    expect(Buffer.from(a)).not.toEqual(Buffer.from(b));
  });

  it("farklı parolalarla farklı anahtarlar üretmeli", async () => {
    const salt = generateSalt();
    const a = await deriveKey(MASTER_PASSWORD, salt, FAST_ITERATIONS);
    const b = await deriveKey("başka-bir-parola", salt, FAST_ITERATIONS);
    expect(Buffer.from(a)).not.toEqual(Buffer.from(b));
  });

  it("kısa parolada WeakMasterPasswordError fırlatmalı", async () => {
    await expect(deriveKey("kisa", generateSalt())).rejects.toThrow(
      WeakMasterPasswordError,
    );
  });

  it("kısa tuzda InvalidParameterError fırlatmalı", async () => {
    await expect(
      deriveKey(MASTER_PASSWORD, new Uint8Array(8), FAST_ITERATIONS),
    ).rejects.toThrow(InvalidParameterError);
  });

  it("düşük iterasyonda InvalidParameterError fırlatmalı", async () => {
    await expect(
      deriveKey(MASTER_PASSWORD, generateSalt(), 1_000),
    ).rejects.toThrow(InvalidParameterError);
  });

  it("generateSalt her seferinde 16 baytluk farklı tuz üretmeli", () => {
    const a = generateSalt();
    const b = generateSalt();
    expect(a.length).toBe(16);
    expect(Buffer.from(a)).not.toEqual(Buffer.from(b));
  });

  it("uçtan uca: parola ile şifrele, aynı parola ile çöz", async () => {
    const { encrypt, decrypt } = await import("../src/core/cipher.js");
    const salt = generateSalt();
    const key = await deriveKey(MASTER_PASSWORD, salt, FAST_ITERATIONS);
    const secret = new TextEncoder().encode("JBSWY3DPEHPK3PXP");
    const payload = encrypt(secret, key);

    const rederivedKey = await deriveKey(MASTER_PASSWORD, salt, FAST_ITERATIONS);
    const decrypted = decrypt(payload, rederivedKey);
    expect(new TextDecoder().decode(decrypted)).toBe("JBSWY3DPEHPK3PXP");
  });
});
