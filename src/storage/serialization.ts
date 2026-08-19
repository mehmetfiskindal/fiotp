import type { EncryptedPayload } from "../core/cipher.js";
import { CorruptVaultError } from "../core/errors.js";

/** Kasa dosyasının şema kimliği ve güncel sürüm numarası. */
export const VAULT_FORMAT = "fiotp-vault";
export const VAULT_VERSION = 1;

/** Kasa dosyasında KDF parametrelerini taşıyan bölüm. */
export interface VaultKdfParams {
  algorithm: "PBKDF2-SHA256";
  iterations: number;
  /** Base64 kodlanmış tuz (16 bayt). */
  salt: string;
}

/** Base64 kodlanmış şifreli yük (IV / şifreli metin / auth tag). */
export interface EncryptedPayloadB64 {
  iv: string;
  ciphertext: string;
  authTag: string;
}

/** Kasa dosyasının tamamı (JSON'a birebir eşlenir). */
export interface VaultFile {
  format: typeof VAULT_FORMAT;
  version: number;
  kdf: VaultKdfParams;
  verifier: EncryptedPayloadB64;
  data: EncryptedPayloadB64;
}

/**
 * Bayt dizisini base64 metnine kodlar.
 */
export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

/**
 * Base64 metnini bayt dizisine çözer.
 *
 * @throws {CorruptVaultError} Girdi geçerli base32 değilse.
 */
export function fromBase64(input: string): Uint8Array {
  const trimmed = input.trim();
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(trimmed)) {
    throw new CorruptVaultError("geçersiz base64 veri");
  }
  try {
    return new Uint8Array(Buffer.from(trimmed, "base64"));
  } catch {
    throw new CorruptVaultError("geçersiz base64 veri");
  }
}

/**
 * Ham şifreli yüğü base64 alanlı biçime dönüştürür.
 */
export function payloadToB64(payload: EncryptedPayload): EncryptedPayloadB64 {
  return {
    iv: toBase64(payload.iv),
    ciphertext: toBase64(payload.ciphertext),
    authTag: toBase64(payload.authTag),
  };
}

/**
 * Base64 alanlı şifreli yüğü ham bayt biçimine dönüştürür.
 *
 * @throws {CorruptVaultError} Alanlar eksik veya base64 geçersizse.
 */
export function payloadFromB64(value: unknown): EncryptedPayload {
  assertObject(value, "şifreli yük");
  const record = value as Record<string, unknown>;

  if (
    typeof record.iv !== "string" ||
    typeof record.ciphertext !== "string" ||
    typeof record.authTag !== "string"
  ) {
    throw new CorruptVaultError("şifreli yük alanları eksik");
  }

  return {
    iv: fromBase64(record.iv),
    ciphertext: fromBase64(record.ciphertext),
    authTag: fromBase64(record.authTag),
  };
}

/**
 * Kasa dosyasını JSON metnine serileştirir.
 */
export function serializeVaultFile(file: VaultFile): string {
  return JSON.stringify(file, null, 2);
}

/**
 * JSON metnini doğrulayıp `VaultFile`'a dönüştürür.
 *
 * @throws {CorruptVaultError} JSON bozuksa veya şema uyuşmuyorsa.
 */
export function parseVaultFile(json: string): VaultFile {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new CorruptVaultError("JSON ayrıştırılamadı");
  }

  assertObject(parsed, "kök nesne");
  const record = parsed as Record<string, unknown>;

  if (record.format !== VAULT_FORMAT) {
    throw new CorruptVaultError(
      `bilinmeyen format "${String(record.format)}" (beklenen: "${VAULT_FORMAT}")`,
    );
  }
  if (record.version !== VAULT_VERSION) {
    throw new CorruptVaultError(
      `desteklenmeyen sürüm ${String(record.version)} (beklenen: ${VAULT_VERSION})`,
    );
  }

  assertObject(record.kdf, "kdf bölümü");
  const kdf = record.kdf as Record<string, unknown>;
  if (kdf.algorithm !== "PBKDF2-SHA256") {
    throw new CorruptVaultError(
      `desteklenmeyen KDF algoritması "${String(kdf.algorithm)}"`,
    );
  }
  if (
    typeof kdf.iterations !== "number" ||
    !Number.isInteger(kdf.iterations) ||
    kdf.iterations < 100_000
  ) {
    throw new CorruptVaultError("KDF iterasyon sayısı geçersiz");
  }
  if (typeof kdf.salt !== "string") {
    throw new CorruptVaultError("KDF tuzu eksik");
  }

  return {
    format: VAULT_FORMAT,
    version: VAULT_VERSION,
    kdf: {
      algorithm: "PBKDF2-SHA256",
      iterations: kdf.iterations,
      salt: kdf.salt,
    },
    verifier: assertPayloadSection(record.verifier, "verifier"),
    data: assertPayloadSection(record.data, "data"),
  };
}

function assertObject(value: unknown, what: string): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new CorruptVaultError(`${what} bir nesne olmalıdır`);
  }
}

function assertPayloadSection(
  value: unknown,
  name: string,
): EncryptedPayloadB64 {
  assertObject(value, `${name} bölümü`);
  const record = value as Record<string, unknown>;
  if (
    typeof record.iv !== "string" ||
    typeof record.ciphertext !== "string" ||
    typeof record.authTag !== "string"
  ) {
    throw new CorruptVaultError(`${name} bölümünün alanları eksik`);
  }
  return {
    iv: record.iv,
    ciphertext: record.ciphertext,
    authTag: record.authTag,
  };
}
