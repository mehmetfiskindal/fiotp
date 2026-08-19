import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LoginThrottle } from "../src/storage/loginThrottle.js";
import { VaultManager } from "../src/storage/vault.js";
import {
  TooManyAttemptsError,
  WrongMasterPasswordError,
} from "../src/core/errors.js";

const PASSWORD = "throttle-master-parola";
const FAST_ITERATIONS = 100_000;

describe("LoginThrottle (birim)", () => {
  it("eşiğe ulaşmadan kilit uygulanmamalı", () => {
    const throttle = new LoginThrottle({ maxAttempts: 3, now: () => 0 });
    throttle.recordFailure("a");
    throttle.recordFailure("a");
    expect(() => throttle.check("a")).not.toThrow();
  });

  it("eşik aşılınca TooManyAttemptsError fırlatmalı", () => {
    let time = 0;
    const throttle = new LoginThrottle({
      maxAttempts: 3,
      baseBackoffMs: 1_000,
      maxBackoffMs: 8_000,
      now: () => time,
    });
    throttle.recordFailure("a");
    throttle.recordFailure("a");
    throttle.recordFailure("a");
    expect(() => throttle.check("a")).toThrow(TooManyAttemptsError);
  });

  it("kilit süresi dolunca sayaç sıfırlanmalı", () => {
    let time = 0;
    const throttle = new LoginThrottle({
      maxAttempts: 2,
      baseBackoffMs: 1_000,
      now: () => time,
    });
    throttle.recordFailure("a");
    throttle.recordFailure("a");
    expect(() => throttle.check("a")).toThrow(TooManyAttemptsError);

    time = 1_001;
    expect(() => throttle.check("a")).not.toThrow();
  });

  it("başarılı deneme sayacı tamamen sıfırlamalı", () => {
    const throttle = new LoginThrottle({ maxAttempts: 2, now: () => 0 });
    throttle.recordFailure("a");
    throttle.recordSuccess("a");
    throttle.recordFailure("a");
    // Yalnızca 1 başarısızlık var (başarı sıfırladı): kilit yok.
    expect(() => throttle.check("a")).not.toThrow();
  });

  it("üstel geri çekilme süreyi ikiye katlamalı", () => {
    let time = 0;
    const throttle = new LoginThrottle({
      maxAttempts: 1,
      baseBackoffMs: 1_000,
      maxBackoffMs: 8_000,
      now: () => time,
    });
    const errors: number[] = [];
    throttle.recordFailure("a");
    try {
      throttle.check("a");
    } catch (error) {
      errors.push((error as TooManyAttemptsError).retryAfterMs);
    }
    // İlk kilit 1000ms; geçince tekrar başarısızlık 2000ms kilitler.
    time = 1_001;
    throttle.check("a"); // durum temizlendi
    throttle.recordFailure("a");
    try {
      throttle.check("a");
    } catch (error) {
      errors.push((error as TooManyAttemptsError).retryAfterMs);
    }
    expect(errors[0]).toBe(1_000);
    expect(errors[1]).toBe(2_000);
  });
});

describe("kasa açılışında oran sınırlama", () => {
  let directory: string;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), "fiotp-throttle-"));
  });

  afterAll(async () => {
    await rm(directory, { recursive: true, force: true });
  });

  it("ardışık başarısızlıkta doğru parola bile kilitlenmeli", async () => {
    const path = join(directory, "vault.json");
    await VaultManager.create(path, PASSWORD, { iterations: FAST_ITERATIONS });

    const throttle = new LoginThrottle({
      maxAttempts: 2,
      baseBackoffMs: 60_000,
    });

    for (let i = 0; i < 2; i++) {
      await expect(
        VaultManager.open(path, "yanlis-parola", {
          loginThrottle: throttle,
        }),
      ).rejects.toThrow(WrongMasterPasswordError);
    }

    await expect(
      VaultManager.open(path, PASSWORD, { loginThrottle: throttle }),
    ).rejects.toThrow(TooManyAttemptsError);
  });

  it("başarılı açılış sonrası yeni denemeler engellenmemeli", async () => {
    const path = join(directory, "reset.json");
    await VaultManager.create(path, PASSWORD, { iterations: FAST_ITERATIONS });

    const throttle = new LoginThrottle({
      maxAttempts: 2,
      baseBackoffMs: 60_000,
    });

    await expect(
      VaultManager.open(path, "yanlis-parola", { loginThrottle: throttle }),
    ).rejects.toThrow(WrongMasterPasswordError);

    const vault = await VaultManager.open(path, PASSWORD, {
      loginThrottle: throttle,
    });
    vault.lock();

    // Başarılı deneme sayacı sıfırladı; hâlâ açılabilmeli.
    await expect(
      VaultManager.open(path, PASSWORD, { loginThrottle: throttle }),
    ).resolves.toBeInstanceOf(VaultManager);
  });

  it("parola değişiminde yanlış mevcut parola da sınırlanmalı", async () => {
    const path = join(directory, "passwd.json");
    await VaultManager.create(path, PASSWORD, { iterations: FAST_ITERATIONS });

    const throttle = new LoginThrottle({
      maxAttempts: 2,
      baseBackoffMs: 60_000,
    });
    const vault = await VaultManager.open(path, PASSWORD, {
      loginThrottle: throttle,
    });

    for (let i = 0; i < 2; i++) {
      await expect(
        vault.changeMasterPassword("yanlis-parola", "yeni-guclu-parola"),
      ).rejects.toThrow(WrongMasterPasswordError);
    }

    await expect(
      vault.changeMasterPassword(PASSWORD, "yeni-guclu-parola"),
    ).rejects.toThrow(TooManyAttemptsError);
    vault.lock();
  });
});
