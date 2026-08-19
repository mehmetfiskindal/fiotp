import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FiotpService } from "../src/service/fiotp.js";
import { base32Encode } from "../src/core/base32.js";
import { generateHOTP } from "../src/core/otp.js";
import {
  InvalidParameterError,
  VaultLockedError,
} from "../src/core/errors.js";
import { createAccount } from "../src/storage/account.js";

const PASSWORD = "hotp-master-password";
const OPTIONS = { iterations: 100_000, autoLockMs: null };

/** RFC 4226 test anahtarı: ASCII "12345678901234567890". */
const HOTP_SECRET = base32Encode(
  new TextEncoder().encode("12345678901234567890"),
);

let directory: string;

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), "fiotp-hotp-"));
});

afterAll(async () => {
  await rm(directory, { recursive: true, force: true });
});

describe("HOTP hesap modeli", () => {
  it("hotp hesabı counter ile oluşturulmalı", () => {
    const account = createAccount({
      type: "hotp",
      account: "alice",
      secret: HOTP_SECRET,
      counter: 0,
    });
    expect(account.type).toBe("hotp");
    expect(account.counter).toBe(0);
  });

  it("hotp hesabı counter olmadan reddedilmeli", () => {
    expect(() =>
      createAccount({ type: "hotp", account: "alice", secret: HOTP_SECRET }),
    ).toThrow(InvalidParameterError);
  });

  it("totp hesabı counter ile reddedilmeli", () => {
    expect(() =>
      createAccount({ account: "alice", secret: HOTP_SECRET, counter: 0 }),
    ).toThrow(InvalidParameterError);
  });

  it("negatif counter reddedilmeli", () => {
    expect(() =>
      createAccount({
        type: "hotp",
        account: "alice",
        secret: HOTP_SECRET,
        counter: -1,
      }),
    ).toThrow(InvalidParameterError);
  });
});

describe("HOTP servis akışı", () => {
  it("URI'den eklenen HOTP hesabı RFC 4226 vektörünü üretmeli", async () => {
    const service = await FiotpService.create(
      join(directory, "hotp.json"),
      PASSWORD,
      OPTIONS,
    );
    const account = service.addAccount(
      `otpauth://hotp/Example:alice?secret=${HOTP_SECRET}&issuer=Example&counter=0`,
    );
    expect(account.type).toBe("hotp");

    const first = service.getCode(account.id);
    expect(first.type).toBe("hotp");
    expect(first.code).toBe("755224"); // RFC 4226 Appendix D, counter=0

    await service.save();
    service.lock();
  });

  it("doğrulama sonrası sayaç ilerlemeli ve kalıcı olmalı", async () => {
    const path = join(directory, "hotp-advance.json");
    const service = await FiotpService.create(path, PASSWORD, OPTIONS);
    const account = service.addAccount({
      type: "hotp",
      account: "alice",
      secret: HOTP_SECRET,
      counter: 0,
    });

    const code0 = service.getCode(account.id);
    expect(await service.verifyCode(account.id, code0.code)).toBe(true);

    // Sayaç 1'e ilerledi: sonraki kod RFC vektörü counter=1 olmalı.
    expect(service.getCode(account.id).code).toBe("287082");

    // Aynı kod tekrar kullanılamamalı (sayaç geçti).
    expect(await service.verifyCode(account.id, code0.code)).toBe(false);

    service.lock();

    const reopened = await FiotpService.open(path, PASSWORD, OPTIONS);
    const [persisted] = reopened.listAccounts();
    expect(persisted!.counter).toBe(1);
    expect(reopened.getCode(persisted!.id).code).toBe("287082");
    reopened.lock();
  });

  it("lookahead penceresi içindeki sayaç kaymasını kabul etmeli", async () => {
    const service = await FiotpService.create(
      join(directory, "hotp-lookahead.json"),
      PASSWORD,
      OPTIONS,
    );
    const account = service.addAccount({
      type: "hotp",
      account: "alice",
      secret: HOTP_SECRET,
      counter: 0,
    });

    // Kullanıcı 5 kod atladı: counter=5'in kodu.
    const secretKey = new TextEncoder().encode("12345678901234567890");
    const skippedCode = generateHOTP(secretKey, 5n);
    expect(await service.verifyCode(account.id, skippedCode)).toBe(true);

    // Sayaç eşleşen değerin bir sonrasına (6) ilerlemeli.
    expect(service.getCode(account.id).code).toBe(
      generateHOTP(secretKey, 6n),
    );
    service.lock();
  });

  it("lookahead dışındaki kod reddedilmeli", async () => {
    const service = await FiotpService.create(
      join(directory, "hotp-outside.json"),
      PASSWORD,
      OPTIONS,
    );
    const account = service.addAccount({
      type: "hotp",
      account: "alice",
      secret: HOTP_SECRET,
      counter: 0,
    });

    const secretKey = new TextEncoder().encode("12345678901234567890");
    const farCode = generateHOTP(secretKey, 10n); // pencere 0-9
    expect(await service.verifyCode(account.id, farCode)).toBe(false);
    expect(service.getCode(account.id).code).toBe("755224"); // sayaç değişmedi
    service.lock();
  });

  it("HOTP hesabı canlı akışa abone olamamalı", async () => {
    const service = await FiotpService.create(
      join(directory, "hotp-subscribe.json"),
      PASSWORD,
      OPTIONS,
    );
    const account = service.addAccount({
      type: "hotp",
      account: "alice",
      secret: HOTP_SECRET,
      counter: 0,
    });
    expect(() => service.subscribe(account.id, () => {})).toThrow(
      InvalidParameterError,
    );
    service.lock();
    expect(() => service.getCode(account.id)).toThrow(VaultLockedError);
  });
});
