import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FiotpService } from "../src/service/fiotp.js";
import { renderQrPng } from "../src/qr/encode.js";
import { VaultLockedError, WrongMasterPasswordError } from "../src/core/errors.js";
import { parseMigrationUri } from "../src/parser/migration.js";

// ─── Test-only helpers: protobufla MigrationPayload URI üretimi ──────────

function encVarint(value: number): Uint8Array {
  const b: number[] = [];
  let v = value >>> 0;
  while (v > 0x7f) { b.push((v & 0x7f) | 0x80); v >>>= 7; }
  b.push(v & 0x7f);
  return new Uint8Array(b);
}

function encFldVarint(field: number, value: number): Uint8Array {
  const tag = encVarint((field << 3) | 0);
  const data = encVarint(value);
  const o = new Uint8Array(tag.length + data.length);
  o.set(tag); o.set(data, tag.length); return o;
}

function encFldBytes(field: number, bytes: Uint8Array): Uint8Array {
  const tag = encVarint((field << 3) | 2);
  const len = encVarint(bytes.length);
  const o = new Uint8Array(tag.length + len.length + bytes.length);
  o.set(tag); o.set(len, tag.length); o.set(bytes, tag.length + len.length); return o;
}

function encFldStr(field: number, s: string): Uint8Array {
  return encFldBytes(field, new TextEncoder().encode(s));
}

function encFldSubmsg(field: number, msg: Uint8Array): Uint8Array {
  return encFldBytes(field, msg);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const o = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let off = 0;
  for (const p of parts) { o.set(p, off); off += p.length; }
  return o;
}

function buildMigrationUri(
  entries: Array<{ secret: Uint8Array; name: string; issuer?: string; algo?: number; digits?: number; type?: number; counter?: number }>,
): string {
  const encoded = entries.map((e) => {
    const fields: Uint8Array[] = [
      encFldBytes(1, e.secret),
      encFldStr(2, e.name),
    ];
    if (e.issuer) fields.push(encFldStr(3, e.issuer));
    if (e.algo !== undefined) fields.push(encFldVarint(4, e.algo));
    if (e.digits !== undefined) fields.push(encFldVarint(5, e.digits));
    if (e.type !== undefined) fields.push(encFldVarint(6, e.type));
    if (e.counter !== undefined) fields.push(encFldVarint(7, e.counter));
    return concat(...fields);
  });
  const payload = concat(...encoded.map((e) => encFldSubmsg(1, e)));
  return `otpauth-migration://offline?data=${Buffer.from(payload).toString("base64")}`;
}

const SAMPLE_SECRET = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad]);
const SAMPLE_SECRET_2 = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
const OTP_TOTP = 2;
const OTP_HOTP = 1;
const ALGO_SHA1 = 1;

// ─── Tests ────────────────────────────────────────────────────────────────

const PASSWORD = "service-master-password";
const SECRET = "JBSWY3DPEHPK3PXP";
const OPTIONS = { iterations: 100_000, autoLockMs: null };
let directory: string;

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), "fiotp-service-"));
});

afterAll(async () => {
  await rm(directory, { recursive: true, force: true });
});

describe("FiotpService", () => {
  it("URI'den hesap ekleyip TOTP üretebilmeli", async () => {
    const service = await FiotpService.create(join(directory, "basic.json"), PASSWORD, OPTIONS);
    const account = service.addAccount(
      `otpauth://totp/Example:alice?secret=${SECRET}&issuer=Example`,
    );
    const result = service.getCode(account.id);

    expect(result.type).toBe("totp");
    expect(result.code).toMatch(/^\d{6}$/);
    if (result.type !== "totp") throw new Error("beklenmeyen tip");
    expect(result.remainingSeconds).toBeGreaterThanOrEqual(1);
    expect(result.remainingSeconds).toBeLessThanOrEqual(30);
    expect(await service.verifyCode(account.id, result.code)).toBe(true);
    await service.save();
    service.lock();
    expect(() => service.getCode(account.id)).toThrow(VaultLockedError);
  });

  it("QR PNG'den hesap ekleyebilmeli", async () => {
    const path = join(directory, "qr.json");
    const service = await FiotpService.create(path, PASSWORD, OPTIONS);
    const uri = `otpauth://totp/QR:alice?secret=${SECRET}&issuer=QR`;
    const account = service.addAccountFromQr(await renderQrPng(uri));
    expect(account.issuer).toBe("QR");
    expect(service.listAccounts({ hideSecrets: true })[0]).not.toHaveProperty("secret");
    service.lock();
  });

  it("hesap silebilmeli ve QR SVG üretebilmeli", async () => {
    const service = await FiotpService.create(join(directory, "manage.json"), PASSWORD, OPTIONS);
    const account = service.addAccount({ account: "alice", secret: SECRET });
    expect(await service.getQrSvg(account.id)).toContain("<svg");
    expect(service.removeAccount(account.id)).toBe(true);
    expect(service.removeAccount(account.id)).toBe(false);
    service.lock();
  });

  it("şifreli backup export/import merge ve replace desteklemeli", async () => {
    const source = await FiotpService.create(join(directory, "source.json"), PASSWORD, OPTIONS);
    source.addAccount({ issuer: "Source", account: "alice", secret: SECRET });
    const backup = await source.exportBackup();

    const target = await FiotpService.create(join(directory, "target.json"), PASSWORD, OPTIONS);
    target.addAccount({ issuer: "Target", account: "bob", secret: "MZXW6YTB" });
    expect(await target.importBackup(backup, PASSWORD, "merge")).toBe(1);
    expect(target.listAccounts()).toHaveLength(2);
    expect(await target.importBackup(backup, PASSWORD, "merge")).toBe(0);
    expect(await target.importBackup(backup, PASSWORD, "replace")).toBe(1);
    expect(target.listAccounts()).toHaveLength(1);
    source.lock();
    target.lock();
  });

  it("yanlış backup parolasını reddetmeli", async () => {
    const source = await FiotpService.create(join(directory, "wrong-source.json"), PASSWORD, OPTIONS);
    source.addAccount({ account: "alice", secret: SECRET });
    const backup = await source.exportBackup();
    const target = await FiotpService.create(join(directory, "wrong-target.json"), PASSWORD, OPTIONS);
    await expect(target.importBackup(backup, "wrong-backup-password", "merge")).rejects.toThrow(
      WrongMasterPasswordError,
    );
    source.lock();
    target.lock();
  });

  it("migration URI'den hesapları içe aktarmalı", async () => {
    const service = await FiotpService.create(join(directory, "migration1.json"), PASSWORD, OPTIONS);
    const uri = buildMigrationUri([
      { secret: SAMPLE_SECRET, name: "alice", issuer: "Google", algo: ALGO_SHA1, digits: 6, type: OTP_TOTP },
      { secret: SAMPLE_SECRET_2, name: "bob", issuer: "GitHub", algo: ALGO_SHA1, digits: 6, type: OTP_HOTP, counter: 10 },
    ]);

    const result = service.importMigration(uri);
    expect(result.added).toBe(2);
    expect(result.skippedMd5).toBe(0);
    expect(result.skippedInvalid).toBe(0);

    const accounts = service.listAccounts();
    expect(accounts).toHaveLength(2);
    const alice = accounts.find((a) => a.account === "alice");
    expect(alice).toBeDefined();
    expect(alice!.issuer).toBe("Google");
    expect(alice!.type).toBe("totp");
    const bob = accounts.find((a) => a.account === "bob");
    expect(bob).toBeDefined();
    expect(bob!.type).toBe("hotp");
    expect(bob!.counter).toBe(10);
    await service.save();
    service.lock();
  });

  it("migration'da tekrar eden hesapları atlamalı", async () => {
    const service = await FiotpService.create(join(directory, "migration2.json"), PASSWORD, OPTIONS);
    const uri = buildMigrationUri([
      { secret: SAMPLE_SECRET, name: "alice", issuer: "Google", algo: ALGO_SHA1, digits: 6, type: OTP_TOTP },
    ]);

    const first = service.importMigration(uri);
    expect(first.added).toBe(1);

    const second = service.importMigration(uri);
    expect(second.added).toBe(0);
    expect(service.listAccounts()).toHaveLength(1);
    service.lock();
  });
});
