import { describe, expect, it } from "vitest";
import { encrypt } from "../src/core/cipher.js";
import { CorruptVaultError } from "../src/core/errors.js";
import {
  fromBase64,
  parseVaultFile,
  payloadFromB64,
  payloadToB64,
  serializeVaultFile,
  toBase64,
  type VaultFile,
} from "../src/storage/serialization.js";

function makeVaultFile(): VaultFile {
  const key = new Uint8Array(32).fill(1);
  const payload = payloadToB64(encrypt(new TextEncoder().encode("veri"), key));
  return {
    format: "fiotp-vault",
    version: 1,
    kdf: {
      algorithm: "PBKDF2-SHA256",
      iterations: 600_000,
      salt: toBase64(new Uint8Array(16).fill(2)),
    },
    verifier: payload,
    data: payload,
  };
}

describe("base64 dönüşümleri", () => {
  it("gidiş-dönüş bozulmamalı", () => {
    const bytes = crypto.getRandomValues(new Uint8Array(48));
    expect(fromBase64(toBase64(bytes))).toEqual(bytes);
  });

  it("geçersiz karakterlerde CorruptVaultError fırlatmalı", () => {
    expect(() => fromBase64("!!geçersiz!!")).toThrow(CorruptVaultError);
  });
});

describe("payload dönüşümleri", () => {
  it("payloadToB64/payloadFromB64 gidiş-dönüşü", () => {
    const key = new Uint8Array(32).fill(3);
    const payload = encrypt(new TextEncoder().encode("test"), key);
    expect(payloadFromB64(payloadToB64(payload))).toEqual(payload);
  });

  it("eksik alanlarda CorruptVaultError fırlatmalı", () => {
    expect(() => payloadFromB64({ iv: "AAAA" })).toThrow(CorruptVaultError);
    expect(() => payloadFromB64(null)).toThrow(CorruptVaultError);
  });
});

describe("parseVaultFile", () => {
  it("geçerli dosyayı ayrıştırmalı", () => {
    const file = makeVaultFile();
    const parsed = parseVaultFile(serializeVaultFile(file));
    expect(parsed).toEqual(file);
  });

  it("bozuk JSON'da CorruptVaultError fırlatmalı", () => {
    expect(() => parseVaultFile("{geçersiz")).toThrow(CorruptVaultError);
  });

  it("yanlış formatta CorruptVaultError fırlatmalı", () => {
    const file = { ...makeVaultFile(), format: "baska-format" };
    expect(() => parseVaultFile(JSON.stringify(file))).toThrow(
      CorruptVaultError,
    );
  });

  it("desteklenmeyen sürüm numarasında CorruptVaultError fırlatmalı", () => {
    const file = { ...makeVaultFile(), version: 99 };
    expect(() => parseVaultFile(JSON.stringify(file))).toThrow(
      CorruptVaultError,
    );
  });

  it("eksik kdf bölümünde CorruptVaultError fırlatmalı", () => {
    const file = makeVaultFile() as unknown as Record<string, unknown>;
    delete file.kdf;
    expect(() => parseVaultFile(JSON.stringify(file))).toThrow(
      CorruptVaultError,
    );
  });

  it("düşük KDF iterasyonunda CorruptVaultError fırlatmalı", () => {
    const file = makeVaultFile();
    file.kdf.iterations = 1_000;
    expect(() => parseVaultFile(JSON.stringify(file))).toThrow(
      CorruptVaultError,
    );
  });

  it("eksik verifier/data bölümlerinde CorruptVaultError fırlatmalı", () => {
    const file = makeVaultFile() as unknown as Record<string, unknown>;
    delete file.verifier;
    expect(() => parseVaultFile(JSON.stringify(file))).toThrow(
      CorruptVaultError,
    );
  });
});
