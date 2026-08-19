import { createHmac, timingSafeEqual } from "node:crypto";
import { base32Decode } from "./base32.js";
import { InvalidParameterError } from "./errors.js";

/** Desteklenen HMAC özet algoritmaları (RFC 6238 §1.2). */
export type OtpAlgorithm = "SHA1" | "SHA256" | "SHA512";

/** OTP üretimi için yapılandırma seçenekleri. */
export interface OtpOptions {
  /** Sonuç kodunun hane sayısı. Varsayılan: 6. RFC 4226 §5.3: 6-8 hane önerilir. */
  digits?: number;
  /** HMAC özet algoritması. Varsayılan: "SHA1" (en yaygın uyumluluk). */
  algorithm?: OtpAlgorithm;
}

/** Bir TOTP kodu ve zamanlama bilgisi. */
export interface TotpCode {
  /** Üretilen sayısal kod (hane sayısı kadar sıfır dolgulu). */
  code: string;
  /** Kodun geçerli olduğu pencerenin kalan süresi (saniye, 1-30 arası). */
  remainingSeconds: number;
  /** Kodun geçerli olduğu toplam pencere süresi (saniye). */
  periodSeconds: number;
}

const DEFAULT_DIGITS = 6;
const DEFAULT_ALGORITHM: OtpAlgorithm = "SHA1";

/** RFC 6238 §5.2'de tanımlı varsayılan zaman adımı. */
export const DEFAULT_PERIOD_SECONDS = 30;

function normalizeAlgorithm(algorithm: OtpAlgorithm | undefined): string {
  if (algorithm === undefined) {
    return DEFAULT_ALGORITHM;
  }
  const allowed: readonly OtpAlgorithm[] = ["SHA1", "SHA256", "SHA512"];
  if (!allowed.includes(algorithm)) {
    throw new InvalidParameterError(
      "algorithm",
      `"${algorithm}" desteklenmiyor (beklenen: ${allowed.join(", ")})`,
    );
  }
  return algorithm;
}

function normalizeDigits(digits: number | undefined): number {
  if (digits === undefined) {
    return DEFAULT_DIGITS;
  }
  if (!Number.isInteger(digits) || digits < 6 || digits > 10) {
    throw new InvalidParameterError(
      "digits",
      "6 ile 10 arasında bir tam sayı olmalıdır",
    );
  }
  return digits;
}

/**
 * RFC 4226'ya tam uyumlu HOTP (HMAC tabanlı tek kullanımlık parola) üretir.
 *
 * Dinamik kesme (dynamic truncation), RFC 4226 §5.3'teki adımları birebir uygular:
 * düşük 4 bit ofset alınır, ofsettten itibaren 31 bit okunur ve mod 10^digits uygulanır.
 *
 * @param secretKey Ham HMAC anahtarı (base32 değil).
 * @param counter 8 baytlık sayaç (RFC 4226 §5.2'de big-endian kodlanır).
 * @param options Hane sayısı ve algoritma seçenekleri.
 * @returns Sayısal HOTP kodu.
 * @throws {InvalidParameterError} Hane sayısı geçersizse.
 */
export function generateHOTP(
  secretKey: Uint8Array,
  counter: bigint,
  options?: OtpOptions,
): string {
  const digits = normalizeDigits(options?.digits);
  const algorithm = normalizeAlgorithm(options?.algorithm);

  if (counter < 0n) {
    throw new InvalidParameterError("counter", "negatif olamaz");
  }
  if (secretKey.length === 0) {
    throw new InvalidParameterError("secretKey", "boş olamaz");
  }

  const counterBytes = new Uint8Array(8);
  let value = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }

  const digest = createHmac(algorithm, secretKey).update(counterBytes).digest();

  const offset = digest[digest.length - 1]! & 0x0f;
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff);

  const otp = binary % 10 ** digits;
  return otp.toString().padStart(digits, "0");
}

/**
 * RFC 6238'e tam uyumlu TOTP üretir: HOTP'yi `floor(unixTime / period)` sayacına uygular.
 *
 * @param base32Secret Base32 kodlanmış gizli anahtar.
 * @param unixTime Unix epoch saniyesi (varsayılan: şu an).
 * @param options Hane sayısı, algoritma ve pencere süresi seçenekleri.
 * @returns Üretilen kod ve zamanlama bilgisi.
 * @throws {InvalidBase32SecretError} Gizli anahtar geçersiz base32 ise.
 * @throws {InvalidParameterError} Diğer geçersiz parametrelerde.
 */
export function generateTOTP(
  base32Secret: string,
  unixTime?: number,
  options?: OtpOptions & { period?: number },
): TotpCode {
  const period = options?.period ?? DEFAULT_PERIOD_SECONDS;
  if (!Number.isInteger(period) || period <= 0) {
    throw new InvalidParameterError("period", "pozitif bir tam sayı olmalıdır");
  }

  const timestamp = unixTime ?? Math.floor(Date.now() / 1000);
  if (!Number.isInteger(timestamp) || timestamp < 0) {
    throw new InvalidParameterError(
      "unixTime",
      "negatif olmayan bir tam sayı (epoch saniyesi) olmalıdır",
    );
  }

  const secretKey = base32Decode(base32Secret);
  const counter = BigInt(Math.floor(timestamp / period));
  const code = generateHOTP(secretKey, counter, options);

  const elapsed = timestamp % period;
  const remainingSeconds = period - elapsed;

  return { code, remainingSeconds, periodSeconds: period };
}

/**
 * Bir TOTP kodunu sabit zamanlı karşılaştırmayla doğrular (zamanlama saldırısına dayanıklı).
 *
 * @param base32Secret Base32 kodlanmış gizli anahtar.
 * @param token Kullanıcının girdiği kod.
 * @param tolerance Yasal saat kayması için kabul edilecek ± pencere sayısı (varsayılan: 1).
 * @param unixTime Doğrulama anı (test edilebilirlik için).
 * @returns Kod geçerliyse `true`.
 */
export function verifyTOTP(
  base32Secret: string,
  token: string,
  options?: OtpOptions & {
    tolerance?: number;
    unixTime?: number;
    period?: number;
  },
): boolean {
  const tolerance = options?.tolerance ?? 1;
  if (!Number.isInteger(tolerance) || tolerance < 0 || tolerance > 5) {
    throw new InvalidParameterError(
      "tolerance",
      "0 ile 5 arasında bir tam sayı olmalıdır",
    );
  }

  const timestamp = options?.unixTime ?? Math.floor(Date.now() / 1000);
  const period = options?.period ?? DEFAULT_PERIOD_SECONDS;
  const digits = options?.digits ?? DEFAULT_DIGITS;

  if (!/^\d+$/.test(token) || token.length !== digits) {
    return false;
  }

  const secretKey = base32Decode(base32Secret);
  const currentCounter = BigInt(Math.floor(timestamp / period));

  for (let drift = -tolerance; drift <= tolerance; drift++) {
    const candidate = generateHOTP(secretKey, currentCounter + BigInt(drift), {
      digits,
      algorithm: options?.algorithm,
    });
    const a = Buffer.from(candidate, "utf8");
    const b = Buffer.from(token, "utf8");
    if (a.length === b.length && timingSafeEqual(a, b)) {
      return true;
    }
  }
  return false;
}
