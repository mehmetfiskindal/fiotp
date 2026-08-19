import { base32Encode } from "../core/base32.js";
import { InvalidMigrationError } from "../core/errors.js";
import type { OtpAlgorithm } from "../core/otp.js";
import type { NewAccountInput } from "../storage/account.js";
import { ProtobufReader } from "./protobuf.js";

/**
 * Google Authenticator "Hesapları aktar" formatı (`otpauth-migration://`).
 *
 * QR kodu, `data` parametresinde base64 kodlanmış bir `MigrationPayload`
 * protobuf mesajı taşır. Gizli anahtarlar burada ham bayt olarak saklanır;
 * fiotp kasası base32 beklediğinden `base32Encode` ile dönüştürülür.
 */

/** Algorithm enum (Google Authenticator `MigrationPayload.Algorithm`). */
const ALGO_SHA1 = 1;
const ALGO_SHA256 = 2;
const ALGO_SHA512 = 3;
const ALGO_MD5 = 4;

/** OtpType enum (`MigrationPayload.OtpType`). */
const OTP_HOTP = 1;
const OTP_TOTP = 2;

/** DigitCount enum (`MigrationPayload.DigitCount`). */
const DIGITS_EIGHT = 2;

/** `parseMigrationUri` sonucu: eklenebilir hesaplar ve atlananların özeti. */
export interface ParsedMigration {
  accounts: NewAccountInput[];
  /** MD5 algoritmalı olduğu için atlanan hesap sayısı (desteklenmiyor). */
  skippedMd5: number;
  /** Gizli anahtar veya adı eksik olduğu için atlanan hesap sayısı. */
  skippedInvalid: number;
}

interface RawOtpParameters {
  secret?: Uint8Array;
  name?: string;
  issuer?: string;
  algorithm?: number;
  digits?: number;
  type?: number;
  counter?: number;
}

/**
 * `otpauth-migration://offline?data=...` URI'sini ayrıştırır ve
 * `NewAccountInput` listesine dönüştürür.
 *
 * @param uri Aktarım URI'si (QR kodundan okunan metin).
 * @throws {InvalidMigrationError} URI, base64 veya protobuf geçersizse.
 */
export function parseMigrationUri(uri: string): ParsedMigration {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    throw new InvalidMigrationError("URI ayrıştırılamadı");
  }
  if (url.protocol !== "otpauth-migration:") {
    throw new InvalidMigrationError("şema otpauth-migration olmalıdır");
  }

  // `data` parametresi ham olarak alınır: base64 "+" karakteri, URLSearchParams
  // tarafından boşluğa çevrileceği için elle ayrıştırılır.
  const match = /(?:^|[&?])data=([^&]*)/.exec(url.search);
  if (match === null) {
    throw new InvalidMigrationError("data parametresi eksik");
  }

  let dataText: string;
  try {
    dataText = decodeURIComponent(match[1]!);
  } catch {
    throw new InvalidMigrationError("data percent-encoding geçersiz");
  }

  let payloadBytes: Uint8Array;
  try {
    // Standart base64; ayrıca URL-güvenli varyant (-_ → +/) tolere edilir.
    const normalized = dataText.replace(/-/g, "+").replace(/_/g, "/");
    payloadBytes = new Uint8Array(Buffer.from(normalized, "base64"));
  } catch {
    throw new InvalidMigrationError("data geçerli base64 değil");
  }

  let rawParams: RawOtpParameters[];
  try {
    rawParams = parseMigrationPayload(payloadBytes);
  } catch {
    throw new InvalidMigrationError("protobuf verisi çözülemedi");
  }

  return convertParameters(rawParams);
}

/** `MigrationPayload` protobuf baytlarını ham parametre listesine çevirir. */
function parseMigrationPayload(bytes: Uint8Array): RawOtpParameters[] {
  const reader = new ProtobufReader(bytes);
  const parameters: RawOtpParameters[] = [];

  while (!reader.eof) {
    const field = reader.readField();
    if (field === null) {
      break;
    }
    if (field.fieldNumber === 1 && field.wireType === 2) {
      const inner = new ProtobufReader(reader.readLengthDelimited());
      parameters.push(parseOtpParameters(inner));
    } else {
      reader.skipField(field.wireType);
    }
  }
  return parameters;
}

/** Tek bir `OtpParameters` mesajını ayrıştırır. */
function parseOtpParameters(reader: ProtobufReader): RawOtpParameters {
  const raw: RawOtpParameters = {};

  while (!reader.eof) {
    const field = reader.readField();
    if (field === null) {
      break;
    }
    switch (field.fieldNumber) {
      case 1: // secret (bytes)
        if (field.wireType === 2) {
          raw.secret = reader.readLengthDelimited();
        } else {
          reader.skipField(field.wireType);
        }
        break;
      case 2: // name (string)
        raw.name = ProtobufReader.decodeUtf8(reader.readLengthDelimited());
        break;
      case 3: // issuer (string)
        raw.issuer = ProtobufReader.decodeUtf8(reader.readLengthDelimited());
        break;
      case 4: // algorithm (enum)
        raw.algorithm = Number(reader.readVarint());
        break;
      case 5: // digits (enum)
        raw.digits = Number(reader.readVarint());
        break;
      case 6: // type (enum)
        raw.type = Number(reader.readVarint());
        break;
      case 7: // counter (uint64)
        raw.counter = Number(reader.readVarint());
        break;
      default:
        reader.skipField(field.wireType);
    }
  }
  return raw;
}

/** Ham parametreleri fiotp hesap girdilerine dönüştürür. */
function convertParameters(rawParams: RawOtpParameters[]): ParsedMigration {
  const accounts: NewAccountInput[] = [];
  let skippedMd5 = 0;
  let skippedInvalid = 0;

  for (const raw of rawParams) {
    if (raw.secret === undefined || raw.secret.length === 0 || !raw.name?.trim()) {
      skippedInvalid += 1;
      continue;
    }

    const algorithm = mapAlgorithm(raw.algorithm);
    if (algorithm === undefined) {
      skippedMd5 += 1;
      continue;
    }

    const type = raw.type === OTP_HOTP ? "hotp" : "totp";
    const digits = raw.digits === DIGITS_EIGHT ? 8 : 6;

    const account: NewAccountInput = {
      type,
      issuer: raw.issuer?.trim() ?? "",
      account: raw.name.trim(),
      secret: base32Encode(raw.secret).replace(/=+$/, ""),
      algorithm,
      digits,
    };
    if (type === "hotp") {
      account.counter =
        typeof raw.counter === "number" && raw.counter >= 0 ? raw.counter : 0;
    }
    accounts.push(account);
  }

  return { accounts, skippedMd5, skippedInvalid };
}

/** Google algoritma enum'unu fiotp algoritmasına eşler; MD5 için `undefined`. */
function mapAlgorithm(value: number | undefined): OtpAlgorithm | undefined {
  switch (value) {
    case ALGO_SHA1:
    case undefined:
      return "SHA1";
    case ALGO_SHA256:
      return "SHA256";
    case ALGO_SHA512:
      return "SHA512";
    default:
      return undefined; // ALGO_MD5 veya bilinmeyen
  }
}
