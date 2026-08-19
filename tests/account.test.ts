import { describe, expect, it } from "vitest";
import {
  accountFromJSON,
  createAccount,
  generateSecret,
  normalizeSecret,
} from "../src/storage/account.js";
import {
  CorruptVaultError,
  InvalidBase32SecretError,
  InvalidParameterError,
} from "../src/core/errors.js";

describe("createAccount", () => {
  it("geçerli girdiyle varsayılanlarla hesap oluşturmalı", () => {
    const account = createAccount({
      account: "kullanici@ornek.com",
      secret: "jbswy3dpehpk3pxp",
    });
    expect(account.secret).toBe("JBSWY3DPEHPK3PXP");
    expect(account.algorithm).toBe("SHA1");
    expect(account.digits).toBe(6);
    expect(account.period).toBe(30);
    expect(account.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  it("özel algoritma, hane sayısı ve periyot kabul etmeli", () => {
    const account = createAccount({
      account: "a",
      secret: "JBSWY3DPEHPK3PXP",
      algorithm: "SHA256",
      digits: 8,
      period: 60,
    });
    expect(account.algorithm).toBe("SHA256");
    expect(account.digits).toBe(8);
    expect(account.period).toBe(60);
  });

  it("boş account alanında InvalidParameterError fırlatmalı", () => {
    expect(() => createAccount({ account: "  ", secret: "JBSWY3DPEHPK3PXP" })).toThrow(
      InvalidParameterError,
    );
  });

  it("geçersiz base32 secret'ta InvalidBase32SecretError fırlatmalı", () => {
    expect(() => createAccount({ account: "a", secret: "ABC1!" })).toThrow(
      InvalidBase32SecretError,
    );
  });

  it("geçersiz algoritma / digits / period değerlerinde hata fırlatmalı", () => {
    const base = { account: "a", secret: "JBSWY3DPEHPK3PXP" };
    expect(() => createAccount({ ...base, algorithm: "MD5" as never })).toThrow(
      InvalidParameterError,
    );
    expect(() => createAccount({ ...base, digits: 5 })).toThrow(
      InvalidParameterError,
    );
    expect(() => createAccount({ ...base, period: 0 })).toThrow(
      InvalidParameterError,
    );
  });
});

describe("normalizeSecret", () => {
  it("küçük harf, boşluk ve padding'i normalize etmeli", () => {
    expect(normalizeSecret(" jbsw y3dp ehpk 3pxp ")).toBe("JBSWY3DPEHPK3PXP");
    expect(normalizeSecret("mzwgczy=")).toBe("MZWGCZY");
  });

  it("geçersiz girdide InvalidBase32SecretError fırlatmalı", () => {
    expect(() => normalizeSecret("012345")).toThrow(InvalidBase32SecretError);
  });
});

describe("generateSecret", () => {
  it("belirtilen bayt uzunluğuna karşılık gelen base32 üretmeli", () => {
    const secret = generateSecret(20);
    expect(secret).toMatch(/^[A-Z2-7]+$/);
    // 20 bayt = 160 bit = 32 base32 karakteri (paddingsiz)
    expect(secret.length).toBe(32);
  });

  it("her çağrıda farklı anahtar üretmeli", () => {
    expect(generateSecret()).not.toBe(generateSecret());
  });

  it("geçersiz uzunlukta InvalidParameterError fırlatmalı", () => {
    expect(() => generateSecret(5)).toThrow(InvalidParameterError);
  });
});

describe("accountFromJSON (katı doğrulama)", () => {
  const valid = {
    id: "00000000-0000-0000-0000-000000000001",
    account: "alice",
    secret: "JBSWY3DPEHPK3PXP",
    createdAt: 1,
  };

  it("eksik opsiyonel alanları varsayılanla doldurmalı", () => {
    const account = accountFromJSON(valid);
    expect(account.type).toBe("totp");
    expect(account.algorithm).toBe("SHA1");
    expect(account.digits).toBe(6);
    expect(account.period).toBe(30);
  });

  it("geçersiz algorithm değerini reddetmeli", () => {
    expect(() => accountFromJSON({ ...valid, algorithm: "MD5" })).toThrow(
      CorruptVaultError,
    );
  });

  it("geçersiz digits değerini reddetmeli", () => {
    expect(() => accountFromJSON({ ...valid, digits: 5 })).toThrow(
      CorruptVaultError,
    );
  });

  it("geçersiz period değerini reddetmeli", () => {
    expect(() => accountFromJSON({ ...valid, period: 0 })).toThrow(
      CorruptVaultError,
    );
  });

  it("geçersiz tip değerini reddetmeli", () => {
    expect(() => accountFromJSON({ ...valid, type: "steam" })).toThrow(
      CorruptVaultError,
    );
  });

  it("hotp tipini ve sayacı ayrıştırmalı", () => {
    const account = accountFromJSON({ ...valid, type: "hotp", counter: 7 });
    expect(account.type).toBe("hotp");
    expect(account.counter).toBe(7);
  });
});
