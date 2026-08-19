import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AccountNotFoundError,
  CorruptVaultError,
  VaultAlreadyExistsError,
  VaultLockedError,
  VaultNotFoundError,
  WeakMasterPasswordError,
  WrongMasterPasswordError,
} from "../src/core/errors.js";
import { VaultManager } from "../src/storage/vault.js";

const MASTER_PASSWORD = "doğru-master-parola";
const FAST_ITERATIONS = 100_000;

let tempDir: string;
let vaultPath: string;

beforeAll(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "fiotp-test-"));
  vaultPath = join(tempDir, "vault.json");
});

afterAll(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

async function createVault(
  path: string = vaultPath,
  autoLockMs: number | null = null,
): Promise<VaultManager> {
  return VaultManager.create(path, MASTER_PASSWORD, {
    iterations: FAST_ITERATIONS,
    autoLockMs,
  });
}

describe("VaultManager yaşam döngüsü", () => {
  it("create → addAccount → save → open: veriler korunmalı", async () => {
    const vault = await createVault();

    const added = vault.addAccount({
      issuer: "GitHub",
      account: "kullanici@ornek.com",
      secret: "jbswy3dpehpk3pxp",
      algorithm: "SHA256",
    });
    vault.addAccount({
      issuer: "Sunucu",
      account: "root",
      secret: "JBSWY3DPEHPK3PXQ",
    });
    await vault.save();
    vault.lock();

    const reopened = await VaultManager.open(vaultPath, MASTER_PASSWORD);
    const accounts = reopened.listAccounts();

    expect(accounts).toHaveLength(2);
    const github = accounts.find((a) => a.issuer === "GitHub");
    expect(github).toBeDefined();
    expect(github!.secret).toBe("JBSWY3DPEHPK3PXP");
    expect(github!.algorithm).toBe("SHA256");
    expect(github!.id).toBe(added.id);
    reopened.lock();
  });

  it("kasa dosyasında düz metin secret veya issuer bulunmamalı", async () => {
    const content = await readFile(vaultPath, "utf8");
    expect(content).not.toContain("JBSWY3DPEHPK3PXP");
    expect(content).not.toContain("GitHub");
    expect(content).not.toContain("kullanici@ornek.com");
  });

  it("save yapılmayan değişiklikler diske yazılmamalı", async () => {
    const vault = await VaultManager.open(vaultPath, MASTER_PASSWORD);
    vault.addAccount({ account: "kaydedilmemeli", secret: "JBSWY3DPEHPK3PXP" });
    vault.lock();

    const reopened = await VaultManager.open(vaultPath, MASTER_PASSWORD);
    expect(reopened.listAccounts()).toHaveLength(2);
    reopened.lock();
  });

  it("updateAccount kimlik ve createdAt'ı korumalı", async () => {
    const vault = await VaultManager.open(vaultPath, MASTER_PASSWORD);
    const [first] = vault.listAccounts();
    const updated = vault.updateAccount(first!.id, {
      issuer: "GitHub Enterprise",
      digits: 8,
    });

    expect(updated.id).toBe(first!.id);
    expect(updated.createdAt).toBe(first!.createdAt);
    expect(updated.issuer).toBe("GitHub Enterprise");
    expect(updated.digits).toBe(8);
    expect(updated.secret).toBe(first!.secret);

    await vault.save();
    vault.lock();

    const reopened = await VaultManager.open(vaultPath, MASTER_PASSWORD);
    expect(reopened.listAccounts()[0]!.issuer).toBe("GitHub Enterprise");
    reopened.lock();
  });

  it("removeAccount hesabı kaldırmalı, save sonrası kalıcı olmalı", async () => {
    const vault = await VaultManager.open(vaultPath, MASTER_PASSWORD);
    const accounts = vault.listAccounts();
    const removed = vault.removeAccount(accounts[1]!.id);
    expect(removed).toBe(true);
    expect(vault.listAccounts()).toHaveLength(1);

    await vault.save();
    vault.lock();

    const reopened = await VaultManager.open(vaultPath, MASTER_PASSWORD);
    expect(reopened.listAccounts()).toHaveLength(1);
    reopened.lock();
  });
});

describe("VaultManager hata durumları", () => {
  it("aynı yolda tekrar create → VaultAlreadyExistsError", async () => {
    await expect(createVault()).rejects.toThrow(VaultAlreadyExistsError);
  });

  it("olmayan dosyayı open → VaultNotFoundError", async () => {
    await expect(
      VaultManager.open(join(tempDir, "yok.json"), MASTER_PASSWORD),
    ).rejects.toThrow(VaultNotFoundError);
  });

  it("yanlış master parola → WrongMasterPasswordError", async () => {
    await expect(
      VaultManager.open(vaultPath, "yanlis-parola"),
    ).rejects.toThrow(WrongMasterPasswordError);
  });

  it("zayıf master parola → WeakMasterPasswordError", async () => {
    await expect(
      VaultManager.create(join(tempDir, "yeni.json"), "kisa", {
        iterations: FAST_ITERATIONS,
      }),
    ).rejects.toThrow(WeakMasterPasswordError);
  });

  it("kurcalanmış data bölümü → CorruptVaultError", async () => {
    const tamperedPath = join(tempDir, "tampered.json");
    const content = JSON.parse(await readFile(vaultPath, "utf8"));

    // base64 şifreli metnin ilk baytını tersle
    const ciphertext = Buffer.from(content.data.ciphertext, "base64");
    ciphertext[0] ^= 0xff;
    content.data.ciphertext = ciphertext.toString("base64");

    const { writeFile } = await import("node:fs/promises");
    await writeFile(tamperedPath, JSON.stringify(content));

    await expect(
      VaultManager.open(tamperedPath, MASTER_PASSWORD),
    ).rejects.toThrow(CorruptVaultError);
  });

  it("bozuk JSON → CorruptVaultError", async () => {
    const brokenPath = join(tempDir, "broken.json");
    const { writeFile } = await import("node:fs/promises");
    await writeFile(brokenPath, "{geçersiz");
    await expect(
      VaultManager.open(brokenPath, MASTER_PASSWORD),
    ).rejects.toThrow(CorruptVaultError);
  });

  it("kilitli kasada işlemler → VaultLockedError", async () => {
    const vault = await createVault(join(tempDir, "lock-test.json"));
    vault.lock();

    expect(vault.isUnlocked).toBe(false);
    expect(() => vault.listAccounts()).toThrow(VaultLockedError);
    expect(() =>
      vault.addAccount({ account: "a", secret: "JBSWY3DPEHPK3PXP" }),
    ).toThrow(VaultLockedError);
    await expect(vault.save()).rejects.toThrow(VaultLockedError);
    expect(() => vault.removeAccount("x")).toThrow(VaultLockedError);
  });

  it("olmayan hesabı updateAccount → AccountNotFoundError", async () => {
    const vault = await VaultManager.open(vaultPath, MASTER_PASSWORD);
    expect(() =>
      vault.updateAccount("olmayan-id", { issuer: "yeni" }),
    ).toThrow(AccountNotFoundError);
    vault.lock();
  });
});

describe("otomatik kilit", () => {
  it("hareketsizlikte kasa kendini kilitlemeli", async () => {
    const autoPath = join(tempDir, "auto.json");
    const vault = await createVault(autoPath, 1_000);

    expect(vault.isUnlocked).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 1_400));

    expect(vault.isUnlocked).toBe(false);
    expect(() => vault.listAccounts()).toThrow(VaultLockedError);
  });

  it("etkinlik sayacı sıfırlandığında kilit gecikmeli", async () => {
    const autoPath = join(tempDir, "auto2.json");
    const vault = await createVault(autoPath, 1_200);

    vault.addAccount({ account: "a", secret: "JBSWY3DPEHPK3PXP" });
    await new Promise((resolve) => setTimeout(resolve, 700));
    vault.listAccounts(); // sayacı sıfırla
    await new Promise((resolve) => setTimeout(resolve, 700));

    expect(vault.isUnlocked).toBe(true); // henüz kilitlenmemiş olmalı

    await new Promise((resolve) => setTimeout(resolve, 1_000));
    expect(vault.isUnlocked).toBe(false);
  });

  it("autoLockMs: null ile otomatik kilit devre dışı olmalı", async () => {
    const autoPath = join(tempDir, "auto3.json");
    const vault = await createVault(autoPath, null);

    await new Promise((resolve) => setTimeout(resolve, 1_200));
    expect(vault.isUnlocked).toBe(true);
    vault.lock();
  });

  it("geçersiz autoLockMs değerinde InvalidParameterError", async () => {
    const { InvalidParameterError } = await import("../src/core/errors.js");
    await expect(
      VaultManager.create(
        join(tempDir, "invalid-autolock.json"),
        MASTER_PASSWORD,
        { iterations: FAST_ITERATIONS, autoLockMs: 10 },
      ),
    ).rejects.toThrow(InvalidParameterError);
  });
});

describe("master parola değiştirme", () => {
  it("parola değişince yeni parola açmalı, eski parola reddedilmeli", async () => {
    const path = join(tempDir, "passwd.json");
    const vault = await createVault(path);
    vault.addAccount({ account: "alice", secret: "JBSWY3DPEHPK3PXP" });
    await vault.save();

    await vault.changeMasterPassword(MASTER_PASSWORD, "yeni-guclu-parola");
    vault.lock();

    await expect(VaultManager.open(path, MASTER_PASSWORD)).rejects.toThrow(
      WrongMasterPasswordError,
    );

    const reopened = await VaultManager.open(path, "yeni-guclu-parola");
    expect(reopened.listAccounts()).toHaveLength(1);
    expect(reopened.listAccounts()[0]!.account).toBe("alice");
    reopened.lock();
  });

  it("yanlış mevcut parola → WrongMasterPasswordError", async () => {
    const path = join(tempDir, "passwd-wrong.json");
    const vault = await createVault(path);
    await expect(
      vault.changeMasterPassword("yanlis-parola", "yeni-guclu-parola"),
    ).rejects.toThrow(WrongMasterPasswordError);
    vault.lock();

    // Kasa hâlâ eski parolayla açılabilir olmalı.
    const reopened = await VaultManager.open(path, MASTER_PASSWORD);
    reopened.lock();
  });

  it("zayıf yeni parola → WeakMasterPasswordError", async () => {
    const path = join(tempDir, "passwd-weak.json");
    const vault = await createVault(path);
    await expect(
      vault.changeMasterPassword(MASTER_PASSWORD, "kisa"),
    ).rejects.toThrow(WeakMasterPasswordError);
    vault.lock();

    const reopened = await VaultManager.open(path, MASTER_PASSWORD);
    reopened.lock();
  });

  it("kilitli kasada parola değişimi → VaultLockedError", async () => {
    const vault = await createVault(join(tempDir, "passwd-locked.json"));
    vault.lock();
    await expect(
      vault.changeMasterPassword(MASTER_PASSWORD, "yeni-guclu-parola"),
    ).rejects.toThrow(VaultLockedError);
  });
});

describe("eşzamanlı yazma", () => {
  it("paralel save çağrıları veriyi bozmamalı", async () => {
    const path = join(tempDir, "concurrent.json");
    const vault = await createVault(path);
    for (let i = 0; i < 20; i++) {
      vault.addAccount({ account: `hesap-${i}`, secret: "JBSWY3DPEHPK3PXP" });
    }

    await Promise.all([vault.save(), vault.save(), vault.save(), vault.save()]);
    vault.lock();

    const reopened = await VaultManager.open(path, MASTER_PASSWORD);
    expect(reopened.listAccounts()).toHaveLength(20);
    reopened.lock();
  });

  it("save ile parola değişimi sırayla çalışmalı", async () => {
    const path = join(tempDir, "concurrent-passwd.json");
    const vault = await createVault(path);
    vault.addAccount({ account: "alice", secret: "JBSWY3DPEHPK3PXP" });

    await Promise.all([
      vault.save(),
      vault.changeMasterPassword(MASTER_PASSWORD, "yeni-guclu-parola"),
    ]);
    vault.lock();

    await expect(VaultManager.open(path, MASTER_PASSWORD)).rejects.toThrow(
      WrongMasterPasswordError,
    );
    const reopened = await VaultManager.open(path, "yeni-guclu-parola");
    expect(reopened.listAccounts()).toHaveLength(1);
    reopened.lock();
  });
});

describe("kasa kurtarma", () => {
  it(".bak önceki iyi sürümü saklamalı ve geri yüklemeli", async () => {
    const path = join(tempDir, "recover.json");
    const vault = await createVault(path);
    vault.addAccount({ account: "alice", secret: "JBSWY3DPEHPK3PXP" });
    await vault.save();
    vault.addAccount({ account: "bob", secret: "MZXW6YTB" });
    await vault.save(); // path = [alice, bob], .bak = [alice]
    vault.lock();

    const { writeFile } = await import("node:fs/promises");
    await writeFile(path, "{bozuk-json");

    await VaultManager.restoreBackup(path);
    const reopened = await VaultManager.open(path, MASTER_PASSWORD);
    const accounts = reopened.listAccounts();
    expect(accounts).toHaveLength(1);
    expect(accounts[0]!.account).toBe("alice");
    reopened.lock();
  });

  it("yedek yoksa restoreBackup → VaultNotFoundError", async () => {
    const path = join(tempDir, "no-backup.json");
    const vault = await createVault(path);
    vault.lock();

    await expect(VaultManager.restoreBackup(path)).rejects.toThrow(
      VaultNotFoundError,
    );
  });
});
