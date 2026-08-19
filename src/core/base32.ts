import { InvalidBase32SecretError } from "./errors.js";

/** RFC 4648 base32 alfabesi. */
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const CHAR_TO_VALUE: ReadonlyMap<string, number> = (() => {
  const map = new Map<string, number>();
  for (let i = 0; i < ALPHABET.length; i++) {
    map.set(ALPHABET[i]!, i);
  }
  return map;
})();

/**
 * Bayt dizisini RFC 4648 base32 metnine kodlar.
 *
 * @param bytes Kodlanacak veri.
 * @returns Padding karakterleriyle (`=`) sonlanan base32 metin.
 */
export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += ALPHABET[(value << (5 - bits)) & 0x1f];
  }

  return output + "=".repeat((8 - (output.length % 8)) % 8);
}

/**
 * Base32 metnini bayt dizisine çözer.
 *
 * OAuth/TOTP ekosistemine özgü yaygın sapmaları tolere eder:
 * - küçük harfler (Google Authenticator küçük harf üretir),
 * - eksik/eksik olmayan padding,
 * - iç boşluklar (bazı sağlayıcılar 4'lük gruplara ayırır).
 *
 * @param input Çözülecek base32 metin.
 * @returns Çözülen bayt dizisi.
 * @throws {InvalidBase32SecretError} Alfabe dışı karakter veya hatalı uzunlukta veri.
 */
export function base32Decode(input: string): Uint8Array {
  const normalized = input.replace(/[\s-]/g, "").replace(/=+$/, "").toUpperCase();

  if (normalized.length === 0) {
    throw new InvalidBase32SecretError("girdi boş");
  }

  const invalidChar = [...normalized].find((c) => !CHAR_TO_VALUE.has(c));
  if (invalidChar !== undefined) {
    throw new InvalidBase32SecretError(
      `alfabe dışı karakter "${invalidChar}" (yalnızca A-Z, 2-7 kabul edilir)`,
    );
  }

  const bytes = new Uint8Array(Math.floor((normalized.length * 5) / 8));
  let bits = 0;
  let value = 0;
  let byteIndex = 0;

  for (const char of normalized) {
    value = (value << 5) | CHAR_TO_VALUE.get(char)!;
    bits += 5;
    if (bits >= 8) {
      bytes[byteIndex++] = (value >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }

  return bytes;
}

/**
 * Verilen metnin geçerli base32 olup olmadığını doğrular.
 * Bu, Kullanıcı tarafından girilen bir gizli anahtarı hata fırlatmadan kontrol etmek için kullanışlıdır.
 *
 * @param input Kontrol edilecek metin.
 */
export function isValidBase32(input: string): boolean {
  try {
    base32Decode(input);
    return true;
  } catch {
    return false;
  }
}
