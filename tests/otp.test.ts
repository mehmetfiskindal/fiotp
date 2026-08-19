import { describe, expect, it } from "vitest";
import {
  generateHOTP,
  generateTOTP,
  verifyTOTP,
} from "../src/core/otp.js";
import { base32Encode } from "../src/core/base32.js";
import { InvalidParameterError } from "../src/core/errors.js";

const sha1Seed = "12345678901234567890";

/** RFC 4226 §Appendix D'deki resmî HOTP-SHA1 test vektörleri. */
const rfc4226Vectors: ReadonlyArray<readonly [bigint, string]> = [
  [0n, "755224"],
  [1n, "287082"],
  [2n, "359152"],
  [3n, "969429"],
  [4n, "338314"],
  [5n, "254676"],
  [6n, "287922"],
  [7n, "162583"],
  [8n, "399871"],
  [9n, "520489"],
];

describe("generateHOTP", () => {
  it("RFC 4226 Appendix D vektörlerini üretmeli", () => {
    const key = new TextEncoder().encode(sha1Seed);
    for (const [counter, expected] of rfc4226Vectors) {
      expect(generateHOTP(key, counter)).toBe(expected);
    }
  });

  it("6 haneden az sayıda önde gelen sıfırı korumalı", () => {
    const key = new TextEncoder().encode(sha1Seed);
    expect(generateHOTP(key, 3n)).toBe("969429");
    expect(generateHOTP(key, 6n)).toBe("287922");
    expect(generateHOTP(key, 6n).length).toBe(6);
  });

  it("8 hanelik kod üretebilmeli", () => {
    const key = new TextEncoder().encode(sha1Seed);
    expect(generateHOTP(key, 0n, { digits: 8 })).toBe("84755224");
    expect(generateHOTP(key, 1n, { digits: 8 })).toBe("94287082");
  });

  it("hane sayısı 6-10 aralığı dışında InvalidParameterError fırlatmalı", () => {
    const key = new TextEncoder().encode(sha1Seed);
    expect(() => generateHOTP(key, 0n, { digits: 5 })).toThrow(
      InvalidParameterError,
    );
    expect(() => generateHOTP(key, 0n, { digits: 11 })).toThrow(
      InvalidParameterError,
    );
    expect(() => generateHOTP(key, 0n, { digits: 6.5 })).toThrow(
      InvalidParameterError,
    );
  });

  it("negatif sayaçta InvalidParameterError fırlatmalı", () => {
    const key = new TextEncoder().encode(sha1Seed);
    expect(() => generateHOTP(key, -1n)).toThrow(InvalidParameterError);
  });

  it("boş anahtarla InvalidParameterError fırlatmalı", () => {
    expect(() => generateHOTP(new Uint8Array(0), 0n)).toThrow(
      InvalidParameterError,
    );
  });
});

/**
 * RFC 6238 §Appendix B'deki resmî TOTP test vektörleri.
 * Kodlar 59. saniyede 8 hane olarak üretilir.
 */
const rfc6238Cases = [
  {
    algorithm: "SHA1" as const,
    seed: "12345678901234567890",
    expected: "94287082",
  },
  {
    algorithm: "SHA256" as const,
    seed: "12345678901234567890123456789012",
    expected: "46119246",
  },
  {
    algorithm: "SHA512" as const,
    seed: "1234567890123456789012345678901234567890123456789012345678901234",
    expected: "90693936",
  },
];

describe("generateTOTP", () => {
  it.each(rfc6238Cases)(
    "RFC 6238 Appendix B vektörü ($algorithm)",
    ({ algorithm, seed, expected }) => {
      const secret = base32Encode(new TextEncoder().encode(seed));
      const result = generateTOTP(secret, 59, { digits: 8, algorithm });
      expect(result.code).toBe(expected);
    },
  );

  it("kalan süreyi doğru hesaplamalı", () => {
    const secret = base32Encode(new TextEncoder().encode(sha1Seed));

    expect(generateTOTP(secret, 0).remainingSeconds).toBe(30);
    expect(generateTOTP(secret, 29).remainingSeconds).toBe(1);
    expect(generateTOTP(secret, 30).remainingSeconds).toBe(30);
    expect(generateTOTP(secret, 45).remainingSeconds).toBe(15);
  });

  it("aynı pencere içindeki zamanlar aynı kodu üretmeli", () => {
    const secret = base32Encode(new TextEncoder().encode(sha1Seed));
    const a = generateTOTP(secret, 1_111_111_111);
    const b = generateTOTP(secret, 1_111_111_130);
    expect(a.code).toBe(b.code);
  });

  it("sonraki pencere farklı kod üretmeli", () => {
    const secret = base32Encode(new TextEncoder().encode(sha1Seed));
    const a = generateTOTP(secret, 1_111_111_111);
    const b = generateTOTP(secret, 1_111_111_111 + 30);
    expect(a.code).not.toBe(b.code);
  });

  it("geçersiz base32 anahtarda InvalidBase32SecretError fırlatmalı", () => {
    expect(() => generateTOTP("ABC1!")).toThrow();
  });

  it("geçersiz period değerinde InvalidParameterError fırlatmalı", () => {
    const secret = base32Encode(new TextEncoder().encode(sha1Seed));
    expect(() => generateTOTP(secret, 0, { period: 0 })).toThrow(
      InvalidParameterError,
    );
    expect(() => generateTOTP(secret, 0, { period: -30 })).toThrow(
      InvalidParameterError,
    );
  });

  it("negatif unixTime'da InvalidParameterError fırlatmalı", () => {
    const secret = base32Encode(new TextEncoder().encode(sha1Seed));
    expect(() => generateTOTP(secret, -1)).toThrow(InvalidParameterError);
  });
});

describe("verifyTOTP", () => {
  const secret = base32Encode(new TextEncoder().encode(sha1Seed));

  it("geçerli kodu kabul etmeli", () => {
    const { code } = generateTOTP(secret, 1_700_000_000);
    expect(verifyTOTP(secret, code, { unixTime: 1_700_000_000 })).toBe(true);
  });

  it("yanlış kodu reddetmeli", () => {
    const { code } = generateTOTP(secret, 1_700_000_000);
    const wrong = code === "000000" ? "000001" : "000000";
    expect(verifyTOTP(secret, wrong, { unixTime: 1_700_000_000 })).toBe(false);
  });

  it("tolerans penceresi içindeki saat kaymasını kabul etmeli", () => {
    const { code } = generateTOTP(secret, 1_700_000_000);
    expect(
      verifyTOTP(secret, code, { unixTime: 1_700_000_000 + 30, tolerance: 1 }),
    ).toBe(true);
    expect(
      verifyTOTP(secret, code, { unixTime: 1_700_000_000 - 30, tolerance: 1 }),
    ).toBe(true);
  });

  it("tolerans dışındaki kaymayı reddetmeli", () => {
    const { code } = generateTOTP(secret, 1_700_000_000);
    expect(
      verifyTOTP(secret, code, { unixTime: 1_700_000_000 + 90, tolerance: 1 }),
    ).toBe(false);
  });

  it("hane sayısı uymayan girdiyi reddetmeli", () => {
    expect(verifyTOTP(secret, "12345", { unixTime: 0 })).toBe(false);
    expect(verifyTOTP(secret, "1234567", { unixTime: 0 })).toBe(false);
    expect(verifyTOTP(secret, "abcdef", { unixTime: 0 })).toBe(false);
  });
});
