import { describe, expect, it } from "vitest";
import {
  buildOtpAuthUriFromData,
  otpAuthToAccountInput,
  parseOtpAuthUri,
} from "../src/parser/otpauth.js";
import { createAccount } from "../src/storage/account.js";
import { InvalidOtpAuthUriError } from "../src/core/errors.js";

const secret = "JBSWY3DPEHPK3PXP";

describe("parseOtpAuthUri", () => {
  it("standart TOTP URI'sini ayrıştırmalı", () => {
    const data = parseOtpAuthUri(
      `otpauth://totp/Example%3Aalice%40example.com?secret=${secret}&issuer=Example&algorithm=SHA1&digits=6&period=30`,
    );
    expect(data).toEqual({
      type: "totp",
      issuer: "Example",
      account: "alice@example.com",
      secret,
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    });
  });

  it("issuer parametresi olmadan label issuer'ını kullanmalı", () => {
    const data = parseOtpAuthUri(`otpauth://totp/Example:alice?secret=${secret}`);
    expect(data.issuer).toBe("Example");
    expect(data.account).toBe("alice");
  });

  it("issuer'sız label'ı kabul etmeli", () => {
    const data = parseOtpAuthUri(`otpauth://totp/alice?secret=${secret}`);
    expect(data.issuer).toBe("");
    expect(data.account).toBe("alice");
  });

  it("küçük harf secret ve algorithm'i normalize etmeli", () => {
    const data = parseOtpAuthUri(
      `otpauth://totp/alice?secret=jbswy3dpehpk3pxp&algorithm=sha256&digits=8&period=60`,
    );
    expect(data.secret).toBe(secret);
    expect(data.algorithm).toBe("SHA256");
    expect(data.digits).toBe(8);
    expect(data.period).toBe(60);
  });

  it("HOTP counter parametresini ayrıştırmalı", () => {
    const data = parseOtpAuthUri(
      `otpauth://hotp/Example:alice?secret=${secret}&issuer=Example&counter=12&digits=8`,
    );
    expect(data.type).toBe("hotp");
    expect(data.counter).toBe(12);
    expect(data.digits).toBe(8);
  });

  it("issuer uyuşmazlığını reddetmeli", () => {
    expect(() =>
      parseOtpAuthUri(`otpauth://totp/Foo:alice?secret=${secret}&issuer=Bar`),
    ).toThrow(InvalidOtpAuthUriError);
  });

  it.each([
    "https://example.com/totp/a?secret=x",
    `otpauth://steam/alice?secret=${secret}`,
    "otpauth://totp/?secret=JBSWY3DPEHPK3PXP",
    "otpauth://totp/alice",
    "otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP",
    `otpauth://totp/alice?secret=${secret}&counter=1`,
    `otpauth://totp/alice?secret=invalid!`,
  ])("geçersiz URI'yi reddetmeli: %s", (uri) => {
    expect(() => parseOtpAuthUri(uri)).toThrow(InvalidOtpAuthUriError);
  });

  it("geçersiz digits, period ve counter değerlerini reddetmeli", () => {
    expect(() => parseOtpAuthUri(`otpauth://totp/a?secret=${secret}&digits=5`)).toThrow(
      InvalidOtpAuthUriError,
    );
    expect(() => parseOtpAuthUri(`otpauth://totp/a?secret=${secret}&period=0`)).toThrow(
      InvalidOtpAuthUriError,
    );
    expect(() => parseOtpAuthUri(`otpauth://hotp/a?secret=${secret}&counter=-1`)).toThrow(
      InvalidOtpAuthUriError,
    );
  });
});

describe("otpauth URI builder", () => {
  it("build → parse gidiş-dönüşü sağlamalı", () => {
    const input = {
      type: "totp" as const,
      issuer: "Example & Co",
      account: "alice@example.com",
      secret,
      algorithm: "SHA512" as const,
      digits: 8,
      period: 45,
    };
    const uri = buildOtpAuthUriFromData(input);
    expect(parseOtpAuthUri(uri)).toEqual(input);
  });

  it("OtpAccount'ı URI'ye dönüştürmeli", () => {
    const account = createAccount({
      issuer: "GitHub",
      account: "alice@example.com",
      secret,
    });
    const parsed = parseOtpAuthUri(
      buildOtpAuthUriFromData({
        type: "totp",
        issuer: account.issuer,
        account: account.account,
        secret: account.secret,
        algorithm: account.algorithm,
        digits: account.digits,
        period: account.period,
      }),
    );
    expect(otpAuthToAccountInput(parsed)).toMatchObject({
      issuer: "GitHub",
      account: "alice@example.com",
      secret,
    });
  });

  it("HOTP verisini hotp kasa girdisine dönüştürmeli", () => {
    const hotp = parseOtpAuthUri(`otpauth://hotp/a?secret=${secret}&counter=7`);
    expect(otpAuthToAccountInput(hotp)).toEqual({
      type: "hotp",
      issuer: "",
      account: "a",
      secret,
      algorithm: "SHA1",
      digits: 6,
      counter: 7,
    });
  });
});
