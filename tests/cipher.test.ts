import { describe, expect, it } from "vitest";
import { decrypt, encrypt } from "../src/core/cipher.js";
import {
  DecryptionError,
  InvalidParameterError,
} from "../src/core/errors.js";

const validKey = new Uint8Array(32).fill(0xab);

describe("AES-256-GCM cipher", () => {
  it("şifrele-çöz gidiş-dönüşü doğru yapmalı", () => {
    const plaintext = new TextEncoder().encode("gizli OTP anahtarı: JBSWY3DPEHPK3PXP");
    const payload = encrypt(plaintext, validKey);
    const decrypted = decrypt(payload, validKey);
    expect(new TextDecoder().decode(decrypted)).toBe(
      "gizli OTP anahtarı: JBSWY3DPEHPK3PXP",
    );
  });

  it("her şifrelemede farklı IV üretmeli (rastgelelik)", () => {
    const plaintext = new TextEncoder().encode("aynı veri");
    const a = encrypt(plaintext, validKey);
    const b = encrypt(plaintext, validKey);
    expect(Buffer.from(a.iv)).not.toEqual(Buffer.from(b.iv));
    expect(Buffer.from(a.ciphertext)).not.toEqual(Buffer.from(b.ciphertext));
  });

  it("boş veri şifrelenip çözülebilmeli", () => {
    const payload = encrypt(new Uint8Array(0), validKey);
    expect(decrypt(payload, validKey)).toEqual(new Uint8Array(0));
  });

  it("yanlış anahtarla DecryptionError fırlatmalı", () => {
    const payload = encrypt(new TextEncoder().encode("veri"), validKey);
    const wrongKey = new Uint8Array(32).fill(0xcd);
    expect(() => decrypt(payload, wrongKey)).toThrow(DecryptionError);
  });

  it("kurcalanmış şifreli metinde DecryptionError fırlatmalı", () => {
    const payload = encrypt(new TextEncoder().encode("veri"), validKey);
    payload.ciphertext[0] ^= 0xff;
    expect(() => decrypt(payload, validKey)).toThrow(DecryptionError);
  });

  it("kurcalanmış auth tag'de DecryptionError fırlatmalı", () => {
    const payload = encrypt(new TextEncoder().encode("veri"), validKey);
    payload.authTag[0] ^= 0xff;
    expect(() => decrypt(payload, validKey)).toThrow(DecryptionError);
  });

  it("32 bayt olmayan anahtarla InvalidParameterError fırlatmalı", () => {
    expect(() => encrypt(new Uint8Array(1), new Uint8Array(31))).toThrow(
      InvalidParameterError,
    );
    expect(() => encrypt(new Uint8Array(1), new Uint8Array(33))).toThrow(
      InvalidParameterError,
    );
  });

  it("hatalı IV uzunluğunda DecryptionError fırlatmalı", () => {
    const payload = encrypt(new Uint8Array(1), validKey);
    expect(() =>
      decrypt({ ...payload, iv: new Uint8Array(11) }, validKey),
    ).toThrow(DecryptionError);
  });
});
