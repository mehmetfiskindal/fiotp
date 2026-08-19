import { InvalidOtpAuthUriError } from "../core/errors.js";
import { normalizeSecret, type NewAccountInput, type OtpAccount } from "../storage/index.js";
import type { OtpAlgorithm } from "../core/otp.js";

/** Google Authenticator Key URI tipleri. */
export type OtpAuthType = "totp" | "hotp";

/** Ayrıştırılmış ve doğrulanmış otpauth URI verisi. */
export interface OtpAuthData {
  type: OtpAuthType;
  issuer: string;
  account: string;
  secret: string;
  algorithm: OtpAlgorithm;
  digits: number;
  period: number;
  counter?: number;
}

const ALGORITHMS: readonly OtpAlgorithm[] = ["SHA1", "SHA256", "SHA512"];

/**
 * `otpauth://totp/...` veya `otpauth://hotp/...` URI'sini ayrıştırır.
 * Unknown query parametreleri ileriye uyumluluk için yok sayılır.
 */
export function parseOtpAuthUri(input: string): OtpAuthData {
  if (typeof input !== "string" || input.trim() === "") {
    throw new InvalidOtpAuthUriError("URI boş olamaz");
  }

  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new InvalidOtpAuthUriError("URI ayrıştırılamadı");
  }

  if (url.protocol !== "otpauth:") {
    throw new InvalidOtpAuthUriError("şema otpauth olmalıdır");
  }
  if (url.hostname !== "totp" && url.hostname !== "hotp") {
    throw new InvalidOtpAuthUriError("tip totp veya hotp olmalıdır");
  }

  const label = decodePart(url.pathname.slice(1), "label");
  if (label.length === 0) {
    throw new InvalidOtpAuthUriError("label boş olamaz");
  }

  const colon = label.indexOf(":");
  const labelIssuer = colon >= 0 ? label.slice(0, colon).trim() : "";
  const account = (colon >= 0 ? label.slice(colon + 1) : label).trim();
  if (account.length === 0) {
    throw new InvalidOtpAuthUriError("account label boş olamaz");
  }

  const issuerParam = url.searchParams.get("issuer")?.trim() ?? "";
  if (labelIssuer !== "" && issuerParam !== "" && labelIssuer !== issuerParam) {
    throw new InvalidOtpAuthUriError(
      `label issuer ("${labelIssuer}") ile issuer parametresi ("${issuerParam}") eşleşmiyor`,
    );
  }

  const rawSecret = url.searchParams.get("secret");
  if (rawSecret === null || rawSecret.trim() === "") {
    throw new InvalidOtpAuthUriError("secret parametresi zorunludur");
  }

  let secret: string;
  try {
    secret = normalizeSecret(rawSecret);
  } catch {
    throw new InvalidOtpAuthUriError("secret geçerli base32 değil");
  }

  const algorithm = parseAlgorithm(url.searchParams.get("algorithm"));
  const digits = parseDigits(url.searchParams.get("digits"));
  const issuer = issuerParam || labelIssuer;

  if (url.hostname === "totp") {
    if (url.searchParams.has("counter")) {
      throw new InvalidOtpAuthUriError("totp URI counter parametresi içeremez");
    }
    const period = parsePositiveInteger(url.searchParams.get("period"), 30, "period");
    return { type: "totp", issuer, account, secret, algorithm, digits, period };
  }

  const rawCounter = url.searchParams.get("counter");
  if (rawCounter === null) {
    throw new InvalidOtpAuthUriError("hotp URI için counter parametresi zorunludur");
  }
  const counter = parseNonNegativeInteger(rawCounter, "counter");
  return { type: "hotp", issuer, account, secret, algorithm, digits, period: 30, counter };
}

/** TOTP/HOTP hesabını standart otpauth URI'sine dönüştürür. */
export function buildOtpAuthUri(account: OtpAccount): string {
  return buildOtpAuthUriFromData({
    type: account.type,
    issuer: account.issuer,
    account: account.account,
    secret: account.secret,
    algorithm: account.algorithm,
    digits: account.digits,
    period: account.period,
    counter: account.counter,
  });
}

/** Ayrıştırılmış TOTP/HOTP verisini otpauth URI'sine dönüştürür. */
export function buildOtpAuthUriFromData(data: OtpAuthData): string {
  validateData(data);
  const label = data.issuer ? `${data.issuer}:${data.account}` : data.account;
  const params = new URLSearchParams({
    secret: normalizeSecret(data.secret),
    algorithm: data.algorithm,
    digits: String(data.digits),
    issuer: data.issuer,
  });
  if (data.type === "totp") {
    params.set("period", String(data.period));
  } else {
    params.set("counter", String(data.counter));
  }
  return `otpauth://${data.type}/${encodeURIComponent(label)}?${params.toString()}`;
}

/** TOTP/HOTP verisini doğrudan `VaultManager.addAccount` girdisine dönüştürür. */
export function otpAuthToAccountInput(data: OtpAuthData): NewAccountInput {
  if (data.type === "hotp") {
    return {
      type: "hotp",
      issuer: data.issuer,
      account: data.account,
      secret: data.secret,
      algorithm: data.algorithm,
      digits: data.digits,
      counter: data.counter ?? 0,
    };
  }
  return {
    type: "totp",
    issuer: data.issuer,
    account: data.account,
    secret: data.secret,
    algorithm: data.algorithm,
    digits: data.digits,
    period: data.period,
  };
}

function decodePart(value: string, name: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new InvalidOtpAuthUriError(`${name} percent-encoding geçersiz`);
  }
}

function parseAlgorithm(value: string | null): OtpAlgorithm {
  const algorithm = (value ?? "SHA1").toUpperCase();
  if (!ALGORITHMS.includes(algorithm as OtpAlgorithm)) {
    throw new InvalidOtpAuthUriError(`desteklenmeyen algorithm "${algorithm}"`);
  }
  return algorithm as OtpAlgorithm;
}

function parseDigits(value: string | null): number {
  return parseInteger(value, 6, "digits", 6, 10);
}

function parsePositiveInteger(value: string | null, fallback: number, name: string): number {
  return parseInteger(value, fallback, name, 1, Number.MAX_SAFE_INTEGER);
}

function parseNonNegativeInteger(value: string, name: string): number {
  return parseInteger(value, 0, name, 0, Number.MAX_SAFE_INTEGER);
}

function parseInteger(
  value: string | null,
  fallback: number,
  name: string,
  minimum: number,
  maximum: number,
): number {
  if (value === null) return fallback;
  if (!/^\d+$/.test(value)) {
    throw new InvalidOtpAuthUriError(`${name} pozitif bir tam sayı olmalıdır`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new InvalidOtpAuthUriError(`${name} değeri geçersiz`);
  }
  return parsed;
}

function validateData(data: OtpAuthData): void {
  if (!data.issuer && !data.account) {
    throw new InvalidOtpAuthUriError("issuer ve account birlikte boş olamaz");
  }
  if (!data.account.trim()) throw new InvalidOtpAuthUriError("account boş olamaz");
  try {
    normalizeSecret(data.secret);
  } catch {
    throw new InvalidOtpAuthUriError("secret geçerli base32 değil");
  }
  parseAlgorithm(data.algorithm);
  parseDigits(String(data.digits));
  if (data.type === "totp") {
    parsePositiveInteger(String(data.period), 30, "period");
  } else {
    parseNonNegativeInteger(String(data.counter), "counter");
  }
}
