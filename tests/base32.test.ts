import { describe, expect, it } from "vitest";
import { base32Decode, base32Encode, isValidBase32 } from "../src/core/base32.js";
import { InvalidBase32SecretError } from "../src/core/errors.js";

describe("base32", () => {
  describe("encode/decode gidiş-dönüş", () => {
    it.each([
      [new Uint8Array([0x00])],
      [new Uint8Array([0xff])],
      [new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f])],
      [new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])],
      [crypto.getRandomValues(new Uint8Array(64))],
    ])("veri %j bozulmadan dönüş yapmalı", (bytes) => {
      expect(base32Decode(base32Encode(bytes))).toEqual(bytes);
    });
  });

  it("RFC 4648 örnek vektörleri", () => {
    expect(base32Encode(new Uint8Array())).toBe("");
    expect(base32Encode(new Uint8Array([0x66]))).toBe("MY======");
    expect(base32Encode(new Uint8Array([0x66, 0x6f]))).toBe("MZXQ====");
    expect(base32Encode(new Uint8Array([0x66, 0x6f, 0x6f]))).toBe("MZXW6===");
    expect(base32Encode(new Uint8Array([0x66, 0x6f, 0x6f, 0x62]))).toBe("MZXW6YQ=");
    expect(base32Encode(new Uint8Array([0x66, 0x6f, 0x6f, 0x62, 0x61]))).toBe("MZXW6YTB");
  });

  it("küçük harf girdiyi çözmelidir (Google Authenticator uyumu)", () => {
    expect(base32Decode("mzwgczy=")).toEqual(base32Decode("MZWGCZY="));
  });

  it("padding olmadan da çözmelidir", () => {
    expect(base32Decode("MZXW6YTB")).toEqual(
      new Uint8Array([0x66, 0x6f, 0x6f, 0x62, 0x61]),
    );
  });

  it("iç boşlukları tolere etmelidir", () => {
    expect(base32Decode("MZXW 6YTB")).toEqual(
      new Uint8Array([0x66, 0x6f, 0x6f, 0x62, 0x61]),
    );
  });

  it("alfabe dışı karakterde InvalidBase32SecretError fırlatmalı", () => {
    expect(() => base32Decode("ABC1")).toThrow(InvalidBase32SecretError);
    expect(() => base32Decode("ABC8")).toThrow(InvalidBase32SecretError);
    expect(() => base32Decode("ABC!")).toThrow(InvalidBase32SecretError);
  });

  it("boş girdide InvalidBase32SecretError fırlatmalı", () => {
    expect(() => base32Decode("")).toThrow(InvalidBase32SecretError);
    expect(() => base32Decode("====")).toThrow(InvalidBase32SecretError);
  });

  it("isValidBase32 hata fırlatmadan sonuç döndürmeli", () => {
    expect(isValidBase32("JBSWY3DPEHPK3PXP")).toBe(true);
    expect(isValidBase32("JBSWY3DPEHPK3PXX!")).toBe(false);
    expect(isValidBase32("")).toBe(false);
  });
});
