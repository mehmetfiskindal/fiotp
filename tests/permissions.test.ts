import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chmod, mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { VaultManager } from "../src/storage/vault.js";

const PASSWORD = "permissions-master-password";
const OPTIONS = { iterations: 100_000, autoLockMs: null };

let directory: string;

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), "fiotp-perm-"));
});

afterAll(async () => {
  await rm(directory, { recursive: true, force: true });
});

async function fileMode(path: string): Promise<number> {
  return (await stat(path)).mode & 0o777;
}

describe("dosya izinleri", () => {
  it("yeni kasa dosyası 0600 izinleriyle oluşturulmalı", async () => {
    const path = join(directory, "fresh.json");
    const vault = await VaultManager.create(path, PASSWORD, OPTIONS);
    vault.lock();
    expect(await fileMode(path)).toBe(0o600);
  });

  it("save sonrası izinler 0600 olarak düzeltilmeli", async () => {
    const path = join(directory, "fix.json");
    const vault = await VaultManager.create(path, PASSWORD, OPTIONS);

    await chmod(path, 0o644); // yanlış izin simülasyonu
    expect(await fileMode(path)).toBe(0o644);

    await vault.save();
    expect(await fileMode(path)).toBe(0o600);
    vault.lock();
  });

  it("yeni oluşturulan kasa dizini 0700 izinleriyle açılmalı", async () => {
    const path = join(directory, "nested", "deep", "vault.json");
    const vault = await VaultManager.create(path, PASSWORD, OPTIONS);
    vault.lock();
    expect(await fileMode(join(directory, "nested"))).toBe(0o700);
    expect(await fileMode(join(directory, "nested", "deep"))).toBe(0o700);
    expect(await fileMode(path)).toBe(0o600);
  });

  it("geçici .tmp dosyası geride kalmamalı", async () => {
    const path = join(directory, "atomic.json");
    const vault = await VaultManager.create(path, PASSWORD, OPTIONS);
    await vault.save();
    vault.lock();
    await expect(stat(`${path}.tmp`)).rejects.toThrow();
  });
});
