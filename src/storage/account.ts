import { randomUUID } from "node:crypto";
import { base32Decode, base32Encode } from "../core/base32.js";
import {
  CorruptVaultError,
  InvalidBase32SecretError,
  InvalidParameterError,
} from "../core/errors.js";
import type { OtpAlgorithm } from "../core/otp.js";

/** OTP hesap tipi. */
export type OtpType = "totp" | "hotp";

/** Depolanan tek bir 2FA hesabı (yalnızca kasa açıkken bellekte düz metin olarak yaşar). */
export interface OtpAccount {
  /** Kasa içinde benzersiz kimlik (UUID v4). */
  id: string;
  /** Hesap tipi. Varsayılan: "totp". */
  type: OtpType;
  /** Hizmet sağlayıcı adı (örn. "GitHub"). Boş bırakılabilir. */
  issuer: string;
  /** Hesap etiketi (örn. "kullanici@ornek.com"). Boş bırakılamaz. */
  account: string;
  /** Normalize edilmiş base32 gizli anahtar (paddingsiz, büyük harf). */
  secret: string;
  /** HMAC algoritması. Varsayılan: "SHA1". */
  algorithm: OtpAlgorithm;
  /** Kod hane sayısı (6-10). Varsayılan: 6. */
  digits: number;
  /** Pencere süresi saniye cinsinden (yalnız TOTP). Varsayılan: 30. */
  period: number;
  /** HOTP sayaç değeri (yalnız HOTP). */
  counter?: number;
  /** Oluşturulma zamanı (Unix epoch, milisaniye). */
  createdAt: number;
}

/** Yeni hesap oluştururken verilen girdi; kimlik ve zaman damgası otomatik üretilir. */
export interface NewAccountInput {
  /** Hesap tipi. Varsayılan: "totp". */
  type?: OtpType;
  issuer?: string;
  account: string;
  /** Base32 gizli anahtar (küçük harf / padding / boşluk toleranslı). */
  secret: string;
  algorithm?: OtpAlgorithm;
  digits?: number;
  period?: number;
  /** HOTP başlangıç sayacı (yalnız HOTP için zorunlu). */
  counter?: number;
}

const ALLOWED_ALGORITHMS: readonly OtpAlgorithm[] = [
  "SHA1",
  "SHA256",
  "SHA512",
];

/**
 * Base32 gizli anahtarı normalize eder: boşluk/tire ayırıcıları temizler,
 * büyük harfe çevirir ve padding'i kaldırır.
 *
 * @param secret Ham girdi.
 * @returns Normalize edilmiş anahtar.
 * @throws {InvalidBase32SecretError} Anahtar geçerli base32 değilse.
 */
export function normalizeSecret(secret: string): string {
  const normalized = secret
    .replace(/[\s-]/g, "")
    .replace(/=+$/, "")
    .toUpperCase();
  base32Decode(normalized); // yalnızca doğrulama için; hata fırlatabilir
  return normalized;
}

/**
 * Yeni bir OTP hesabı oluşturur ve girdiyi eksiksiz doğrular.
 *
 * @param input Hesap bilgileri.
 * @returns Doğrulanmış, kimliklenmiş hesap.
 * @throws {InvalidBase32SecretError} Gizli anahtar geçersizse.
 * @throws {InvalidParameterError} Diğer alanlar geçersizse.
 */
export function createAccount(input: NewAccountInput): OtpAccount {
  const issuer = input.issuer?.trim() ?? "";
  const account = input.account.trim();

  if (account.length === 0) {
    throw new InvalidParameterError("account", "boş olamaz");
  }

  const type = input.type ?? "totp";
  if (type !== "totp" && type !== "hotp") {
    throw new InvalidParameterError(
      "type",
      `"${type}" desteklenmiyor (beklenen: totp, hotp)`,
    );
  }

  const secret = normalizeSecret(input.secret);

  const algorithm = input.algorithm ?? "SHA1";
  if (!ALLOWED_ALGORITHMS.includes(algorithm)) {
    throw new InvalidParameterError(
      "algorithm",
      `"${algorithm}" desteklenmiyor (beklenen: ${ALLOWED_ALGORITHMS.join(", ")})`,
    );
  }

  const digits = input.digits ?? 6;
  if (!Number.isInteger(digits) || digits < 6 || digits > 10) {
    throw new InvalidParameterError(
      "digits",
      "6 ile 10 arasında bir tam sayı olmalıdır",
    );
  }

  const period = input.period ?? 30;
  if (!Number.isInteger(period) || period <= 0) {
    throw new InvalidParameterError(
      "period",
      "pozitif bir tam sayı olmalıdır",
    );
  }

  if (type === "hotp") {
    if (input.counter === undefined) {
      throw new InvalidParameterError(
        "counter",
        "HOTP hesabı için zorunludur",
      );
    }
    if (!Number.isInteger(input.counter) || input.counter < 0) {
      throw new InvalidParameterError(
        "counter",
        "negatif olmayan bir tam sayı olmalıdır",
      );
    }
    return {
      id: randomUUID(),
      type,
      issuer,
      account,
      secret,
      algorithm,
      digits,
      period,
      counter: input.counter,
      createdAt: Date.now(),
    };
  }

  if (input.counter !== undefined) {
    throw new InvalidParameterError(
      "counter",
      "yalnız HOTP hesapları için geçerlidir",
    );
  }

  return {
    id: randomUUID(),
    type,
    issuer,
    account,
    secret,
    algorithm,
    digits,
    period,
    createdAt: Date.now(),
  };
}

/**
 * Hesabı kasa JSON'unda saklanacak düz metin biçimine indirger.
 * Kimlik ve ayarlar korunur; secret normalize edilmiş olarak zaten saklanır.
 */
export function accountToJSON(account: OtpAccount): OtpAccount {
  return { ...account };
}

/**
 * Kasa JSON'ından okunan ham nesneyi `OtpAccount`'a doğrular ve dönüştürür.
 *
 * @param value Ham nesne.
 * @throws {CorruptVaultError} Alanlar eksik veya geçersizse.
 */
export function accountFromJSON(value: unknown): OtpAccount {
  if (typeof value !== "object" || value === null) {
    throw new CorruptVaultError("hesap kaydı bir nesne değil");
  }
  const record = value as Record<string, unknown>;

  const stringFields = ["id", "account", "secret"] as const;
  for (const field of stringFields) {
    if (typeof record[field] !== "string") {
      throw new CorruptVaultError(`hesap alanı "${field}" eksik veya metin değil`);
    }
  }
  try {
    const type = parseType(record.type);
    const base = {
      id: record.id as string,
      type,
      issuer: typeof record.issuer === "string" ? record.issuer : "",
      account: record.account as string,
      secret: normalizeSecret(record.secret as string),
      algorithm: parseStoredAlgorithm(record.algorithm),
      digits: parseStoredDigits(record.digits),
      period: parseStoredPeriod(record.period),
      createdAt:
        typeof record.createdAt === "number" && record.createdAt > 0
          ? record.createdAt
          : 0,
    };
    if (type === "hotp") {
      const counter =
        typeof record.counter === "number" &&
        Number.isInteger(record.counter) &&
        record.counter >= 0
          ? record.counter
          : 0;
      return { ...base, counter };
    }
    return base;
  } catch (error) {
    if (error instanceof InvalidBase32SecretError) {
      throw new CorruptVaultError("hesap gizli anahtarı geçersiz base32");
    }
    throw error;
  }
}

function parseType(value: unknown): OtpType {
  if (value === undefined) return "totp";
  if (value === "totp" || value === "hotp") return value;
  throw new CorruptVaultError(`geçersiz hesap tipi "${String(value)}"`);
}

function parseStoredAlgorithm(value: unknown): OtpAlgorithm {
  if (value === undefined) return "SHA1";
  if (typeof value === "string" && (ALLOWED_ALGORITHMS as readonly string[]).includes(value)) {
    return value as OtpAlgorithm;
  }
  throw new CorruptVaultError(`geçersiz algoritma "${String(value)}"`);
}

function parseStoredDigits(value: unknown): number {
  if (value === undefined) return 6;
  if (typeof value === "number" && Number.isInteger(value) && value >= 6 && value <= 10) {
    return value;
  }
  throw new CorruptVaultError(`geçersiz hane sayısı "${String(value)}"`);
}

function parseStoredPeriod(value: unknown): number {
  if (value === undefined) return 30;
  if (typeof value === "number" && Number.isInteger(value) && value > 0) {
    return value;
  }
  throw new CorruptVaultError(`geçersiz pencere süresi "${String(value)}"`);
}

/**
 * Belirli bir uzunlukta güvenli rastgele base32 gizli anahtar üretir
 * (yeni hesaplar için kullanışlıdır).
 *
 * @param byteLength Anahtar uzunluğu bayt cinsinden (varsayılan: 20 = 160 bit).
 * @returns Base32 kodlanmış gizli anahtar.
 */
export function generateSecret(byteLength: number = 20): string {
  if (!Number.isInteger(byteLength) || byteLength < 10 || byteLength > 64) {
    throw new InvalidParameterError(
      "byteLength",
      "10 ile 64 arasında bir tam sayı olmalıdır",
    );
  }
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base32Encode(bytes).replace(/=+$/, "");
}
