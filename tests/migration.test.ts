import { describe, it, expect } from "vitest";
import { ProtobufReader } from "../src/parser/protobuf.js";
import { parseMigrationUri } from "../src/parser/migration.js";
import { InvalidMigrationError } from "../src/core/errors.js";
import { base32Decode } from "../src/core/base32.js";
import { generateHOTP } from "../src/core/otp.js";

// ─── Protobuf encoder (test-only) ────────────────────────────────────────

function encodeVarint(value: number): Uint8Array {
  const bytes: number[] = [];
  let v = value >>> 0;
  while (v > 0x7f) {
    bytes.push((v & 0x7f) | 0x80);
    v >>>= 7;
  }
  bytes.push(v & 0x7f);
  return new Uint8Array(bytes);
}

function encodeFieldVarint(fieldNumber: number, value: number): Uint8Array {
  const tag = encodeVarint((fieldNumber << 3) | 0);
  const data = encodeVarint(value);
  const out = new Uint8Array(tag.length + data.length);
  out.set(tag);
  out.set(data, tag.length);
  return out;
}

function encodeFieldBytes(fieldNumber: number, bytes: Uint8Array): Uint8Array {
  const tag = encodeVarint((fieldNumber << 3) | 2);
  const len = encodeVarint(bytes.length);
  const out = new Uint8Array(tag.length + len.length + bytes.length);
  out.set(tag);
  out.set(len, tag.length);
  out.set(bytes, tag.length + len.length);
  return out;
}

function encodeFieldString(fieldNumber: number, str: string): Uint8Array {
  return encodeFieldBytes(fieldNumber, new TextEncoder().encode(str));
}

function encodeFieldSubmessage(fieldNumber: number, message: Uint8Array): Uint8Array {
  return encodeFieldBytes(fieldNumber, message);
}

function encodeOtpParameters(opts: {
  secret: Uint8Array;
  name: string;
  issuer?: string;
  algorithm?: number;
  digits?: number;
  type?: number;
  counter?: number;
}): Uint8Array {
  const fields: Uint8Array[] = [];
  fields.push(encodeFieldBytes(1, opts.secret));
  fields.push(encodeFieldString(2, opts.name));
  if (opts.issuer) fields.push(encodeFieldString(3, opts.issuer));
  if (opts.algorithm !== undefined) fields.push(encodeFieldVarint(4, opts.algorithm));
  if (opts.digits !== undefined) fields.push(encodeFieldVarint(5, opts.digits));
  if (opts.type !== undefined) fields.push(encodeFieldVarint(6, opts.type));
  if (opts.counter !== undefined) fields.push(encodeFieldVarint(7, opts.counter));
  return concat(fields);
}

function encodeMigrationPayload(entries: Uint8Array[]): Uint8Array {
  const fields: Uint8Array[] = [];
  for (const entry of entries) {
    fields.push(encodeFieldSubmessage(1, entry));
  }
  return concat(fields);
}

function concat(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function buildMigrationUri(payload: Uint8Array): string {
  const b64 = Buffer.from(payload).toString("base64");
  return `otpauth-migration://offline?data=${b64}`;
}

// ─── Helpers ──────────────────────────────────────────────────────────────

const ALGO_SHA1 = 1;
const ALGO_SHA256 = 2;
const ALGO_SHA512 = 3;
const ALGO_MD5 = 4;

const OTP_HOTP = 1;
const OTP_TOTP = 2;

// "JBSWY3DPEHPK3PXP" decoded = 8 bytes [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad]
const SAMPLE_SECRET = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad]);
const SAMPLE_SECRET_2 = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);

// ─── Tests ────────────────────────────────────────────────────────────────

describe("ProtobufReader", () => {
  it("okuyucu boş tamponda eof döndürür", () => {
    const reader = new ProtobufReader(new Uint8Array(0));
    expect(reader.eof).toBe(true);
    expect(reader.readField()).toBeNull();
  });

  it("varint okur", () => {
    const reader = new ProtobufReader(new Uint8Array([42]));
    expect(reader.readVarint()).toBe(42n);
    expect(reader.eof).toBe(true);
  });

  it("çoklu byte varint okur", () => {
    // 300 = 0x12C → encoding: 0xAC 0x02
    const reader = new ProtobufReader(new Uint8Array([0xac, 0x02]));
    expect(reader.readVarint()).toBe(300n);
  });

  it("length-delimited okur", () => {
    // field 1, wire 2, length 3, data [1,2,3]
    const data = new Uint8Array([0x0a, 0x03, 0x01, 0x02, 0x03]);
    const reader = new ProtobufReader(data);
    const field = reader.readField()!;
    expect(field.fieldNumber).toBe(1);
    expect(field.wireType).toBe(2);
    expect(reader.readLengthDelimited()).toEqual(new Uint8Array([1, 2, 3]));
  });

  it("skipField(0) varint atlar", () => {
    // field 5, wire 0, value 7
    const data = new Uint8Array([0x28, 0x07]);
    const reader = new ProtobufReader(data);
    const field = reader.readField()!;
    expect(field.fieldNumber).toBe(5);
    expect(field.wireType).toBe(0);
    reader.skipField(0);
    expect(reader.eof).toBe(true);
  });

  it("bilinmeyen wire type hata fırlatır", () => {
    // field 1, wire type 3 (start group — deprecated, desteklenmiyor)
    const reader = new ProtobufReader(new Uint8Array([0x0b]));
    const field = reader.readField()!;
    expect(() => reader.skipField(field.wireType)).toThrow("desteklenmeyen wire type");
  });

  it("decodeUtf8 baytları UTF-8 metne çevirir", () => {
    const bytes = new TextEncoder().encode("Merhaba dünya");
    expect(ProtobufReader.decodeUtf8(bytes)).toBe("Merhaba dünya");
  });
});

describe("parseMigrationUri", () => {
  it("tek TOTP hesabını doğru ayrıştırır", () => {
    const entry = encodeOtpParameters({
      secret: SAMPLE_SECRET,
      name: "alice@example.com",
      issuer: "Google",
      algorithm: ALGO_SHA1,
      digits: 6,
      type: OTP_TOTP,
    });
    const payload = encodeMigrationPayload([entry]);
    const uri = buildMigrationUri(payload);

    const result = parseMigrationUri(uri);
    expect(result.accounts).toHaveLength(1);
    expect(result.skippedMd5).toBe(0);
    expect(result.skippedInvalid).toBe(0);

    const account = result.accounts[0]!;
    expect(account.type).toBe("totp");
    expect(account.issuer).toBe("Google");
    expect(account.account).toBe("alice@example.com");
    expect(account.algorithm).toBe("SHA1");
    expect(account.digits).toBe(6);
    // secret decode edildiğinde orijinal baytlarla eşleşmeli
    expect(base32Decode(account.secret)).toEqual(SAMPLE_SECRET);
  });

  it("HOTP hesabını counter ile ayrıştırır", () => {
    const entry = encodeOtpParameters({
      secret: SAMPLE_SECRET,
      name: "bob",
      issuer: "GitHub",
      algorithm: ALGO_SHA1,
      digits: 6,
      type: OTP_HOTP,
      counter: 42,
    });
    const payload = encodeMigrationPayload([entry]);
    const uri = buildMigrationUri(payload);

    const result = parseMigrationUri(uri);
    expect(result.accounts).toHaveLength(1);
    expect(result.accounts[0]!.type).toBe("hotp");
    expect(result.accounts[0]!.counter).toBe(42);
    expect(result.accounts[0]!.issuer).toBe("GitHub");
  });

  it("birden çok hesabı ayrıştırır", () => {
    const entry1 = encodeOtpParameters({
      secret: SAMPLE_SECRET,
      name: "alice",
      issuer: "Google",
      algorithm: ALGO_SHA1,
      digits: 6,
      type: OTP_TOTP,
    });
    const entry2 = encodeOtpParameters({
      secret: SAMPLE_SECRET_2,
      name: "bob@company.com",
      issuer: "Slack",
      algorithm: ALGO_SHA256,
      digits: 2, // DIGITS_EIGHT = 2 → 8 hane
      type: OTP_TOTP,
    });
    const payload = encodeMigrationPayload([entry1, entry2]);
    const uri = buildMigrationUri(payload);

    const result = parseMigrationUri(uri);
    expect(result.accounts).toHaveLength(2);
    expect(result.accounts[0]!.account).toBe("alice");
    expect(result.accounts[0]!.algorithm).toBe("SHA1");
    expect(result.accounts[0]!.digits).toBe(6);
    expect(result.accounts[1]!.account).toBe("bob@company.com");
    expect(result.accounts[1]!.algorithm).toBe("SHA256");
    expect(result.accounts[1]!.digits).toBe(8);
  });

  it("SHA512 algoritmasını destekler", () => {
    const entry = encodeOtpParameters({
      secret: SAMPLE_SECRET,
      name: "test",
      algorithm: ALGO_SHA512,
      digits: 6,
      type: OTP_TOTP,
    });
    const payload = encodeMigrationPayload([entry]);
    const uri = buildMigrationUri(payload);

    const result = parseMigrationUri(uri);
    expect(result.accounts[0]!.algorithm).toBe("SHA512");
  });

  it("MD5 hesaplarını atlar ve sayar", () => {
    const entryMd5 = encodeOtpParameters({
      secret: SAMPLE_SECRET,
      name: "md5user",
      algorithm: ALGO_MD5,
      digits: 6,
      type: OTP_TOTP,
    });
    const entryGood = encodeOtpParameters({
      secret: SAMPLE_SECRET,
      name: "gooduser",
      algorithm: ALGO_SHA1,
      digits: 6,
      type: OTP_TOTP,
    });
    const payload = encodeMigrationPayload([entryMd5, entryGood]);
    const uri = buildMigrationUri(payload);

    const result = parseMigrationUri(uri);
    expect(result.accounts).toHaveLength(1);
    expect(result.accounts[0]!.account).toBe("gooduser");
    expect(result.skippedMd5).toBe(1);
  });

  it("eksik secret'ı atlar", () => {
    const entry = encodeOtpParameters({
      secret: new Uint8Array(0),
      name: "nosecret",
      algorithm: ALGO_SHA1,
      digits: 6,
      type: OTP_TOTP,
    });
    const payload = encodeMigrationPayload([entry]);
    const uri = buildMigrationUri(payload);

    const result = parseMigrationUri(uri);
    expect(result.accounts).toHaveLength(0);
    expect(result.skippedInvalid).toBe(1);
  });

  it("eksik name'i atlar", () => {
    const entry = encodeFieldBytes(1, SAMPLE_SECRET); // sadece secret, name yok
    const payload = encodeMigrationPayload([entry]);
    const uri = buildMigrationUri(payload);

    const result = parseMigrationUri(uri);
    expect(result.accounts).toHaveLength(0);
    expect(result.skippedInvalid).toBe(1);
  });

  it("varsayılan olarak TOTP ve 6 hane kullanır", () => {
    const entry = encodeOtpParameters({
      secret: SAMPLE_SECRET,
      name: "defaults",
      // algorithm, digits, type belirtilmemiş
    });
    const payload = encodeMigrationPayload([entry]);
    const uri = buildMigrationUri(payload);

    const result = parseMigrationUri(uri);
    expect(result.accounts[0]!.type).toBe("totp");
    expect(result.accounts[0]!.algorithm).toBe("SHA1");
    expect(result.accounts[0]!.digits).toBe(6);
    expect(result.accounts[0]!.counter).toBeUndefined();
  });

  it("issuer olmayan hesapları boş issuer ile işler", () => {
    const entry = encodeOtpParameters({
      secret: SAMPLE_SECRET,
      name: "noissuer",
      algorithm: ALGO_SHA1,
      digits: 6,
      type: OTP_TOTP,
    });
    const payload = encodeMigrationPayload([entry]);
    const uri = buildMigrationUri(payload);

    const result = parseMigrationUri(uri);
    expect(result.accounts[0]!.issuer).toBe("");
  });

  it("URL-güvenli base64 (-_) tolerans gösterir", () => {
    const entry = encodeOtpParameters({
      secret: SAMPLE_SECRET,
      name: "test",
      algorithm: ALGO_SHA1,
      digits: 6,
      type: OTP_TOTP,
    });
    const payload = encodeMigrationPayload([entry]);
    let b64 = Buffer.from(payload).toString("base64");
    // base64url varyantına çevir
    b64 = b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const uri = `otpauth-migration://offline?data=${b64}`;

    const result = parseMigrationUri(uri);
    expect(result.accounts).toHaveLength(1);
  });

  it("geçersiz URI şeması fırlatır", () => {
    expect(() =>
      parseMigrationUri("otpauth://totp/test?secret=JBSWY3DPEHPK3PXP"),
    ).toThrow(InvalidMigrationError);
    expect(() =>
      parseMigrationUri("otpauth://totp/test?secret=JBSWY3DPEHPK3PXP"),
    ).toThrow("şema otpauth-migration olmalıdır");
  });

  it("data parametresi eksikse fırlatır", () => {
    expect(() =>
      parseMigrationUri("otpauth-migration://offline?foo=bar"),
    ).toThrow("data parametresi eksik");
  });

  it("geçersiz base64 fırlatır", () => {
    // Node Buffer.from toleranslıdır; geçersiz base64 bytes üretir ama protobuf çözemeyeceği
    // için InvalidMigrationError fırlatılır.
    expect(() =>
      parseMigrationUri("otpauth-migration://offline?data=!!!invalid!!!"),
    ).toThrow(InvalidMigrationError);
  });

  it("bozuk protobuf fırlatır", () => {
    // Geçerli base64 ama anlamsız protobuf içeriği
    const garbage = Buffer.from("not protobuf data").toString("base64");
    expect(() =>
      parseMigrationUri(`otpauth-migration://offline?data=${garbage}`),
    ).toThrow("protobuf verisi çözülemedi");
  });

  it("tampon yetersizse fırlatır", () => {
    const entry = encodeOtpParameters({
      secret: SAMPLE_SECRET,
      name: "test",
      algorithm: ALGO_SHA1,
      digits: 6,
      type: OTP_TOTP,
    });
    const payload = encodeMigrationPayload([entry]);
    // Payload'u kes — sadece ilk baytları al
    const truncated = payload.slice(0, 3);
    const b64 = Buffer.from(truncated).toString("base64");
    expect(() =>
      parseMigrationUri(`otpauth-migration://offline?data=${b64}`),
    ).toThrow();
  });

  it("HOTP counter 0 ile ayrıştırır", () => {
    const entry = encodeOtpParameters({
      secret: SAMPLE_SECRET,
      name: "hotp-zero",
      algorithm: ALGO_SHA1,
      digits: 6,
      type: OTP_HOTP,
      counter: 0,
    });
    const payload = encodeMigrationPayload([entry]);
    const uri = buildMigrationUri(payload);

    const result = parseMigrationUri(uri);
    expect(result.accounts[0]!.counter).toBe(0);
  });
});
