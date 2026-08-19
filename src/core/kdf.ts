import { pbkdf2 as pbkdf2Callback, randomBytes } from "node:crypto";
import { promisify } from "node:util";
import { InvalidParameterError, WeakMasterPasswordError } from "./errors.js";

const pbkdf2 = promisify(pbkdf2Callback);

/** PBKDF2-SHA256 için OWASP önerisi iterasyon sayısı. */
export const DEFAULT_PBKDF2_ITERATIONS = 600_000;

/** Türetilmiş AES-256 anahtarının bayt uzunluğu. */
export const DERIVED_KEY_LENGTH_BYTES = 32;

/** Rastgele tuzun bayt uzunluğu. */
export const SALT_LENGTH_BYTES = 16;

/** Master parola için kabul edilen minimum uzunluk. */
export const MIN_MASTER_PASSWORD_LENGTH = 8;

/**
 * Master paroladan PBKDF2-HMAC-SHA256 ile 32 baytlık AES anahtarı türetir.
 *
 * Aynı (parola, tuz, iterasyon) üçlüsü her zaman aynı anahtarı üretir;
 * farklı tuzlar aynı paroladan tamamen farklı anahtarlar türetir.
 *
 * @param masterPassword Kullanıcının master parolası.
 * @param salt En az 16 baytluk tuz.
 * @param iterations PBKDF2 iterasyon sayısı (varsayılan: 600.000).
 * @returns 32 baytlık anahtar (AES-256-GCM ile kullanım için).
 * @throws {WeakMasterPasswordError} Parola 8 karakterden kısaysa.
 * @throws {InvalidParameterError} Tuz veya iterasyon sayısı geçersizse.
 */
export async function deriveKey(
  masterPassword: string,
  salt: Uint8Array,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS,
): Promise<Uint8Array> {
  if (masterPassword.length < MIN_MASTER_PASSWORD_LENGTH) {
    throw new WeakMasterPasswordError();
  }
  if (salt.length < SALT_LENGTH_BYTES) {
    throw new InvalidParameterError(
      "salt",
      `en az ${SALT_LENGTH_BYTES} bayt olmalıdır (alen: ${salt.length})`,
    );
  }
  if (!Number.isInteger(iterations) || iterations < 100_000) {
    throw new InvalidParameterError(
      "iterations",
      "en az 100.000 olmalıdır (güvenlik eşiği)",
    );
  }

  const key = await pbkdf2(
    masterPassword,
    salt,
    iterations,
    DERIVED_KEY_LENGTH_BYTES,
    "sha256",
  );
  return new Uint8Array(key);
}

/**
 * Şifreleme amaçlı kriptografik olarak güvenli rastgele tuz üretir.
 *
 * @returns 16 baytluk rastgele tuz.
 */
export function generateSalt(): Uint8Array {
  return new Uint8Array(randomBytes(SALT_LENGTH_BYTES));
}
