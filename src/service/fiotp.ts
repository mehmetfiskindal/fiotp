import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { timingSafeEqual } from "node:crypto";
import {
  buildOtpAuthUri,
  otpAuthToAccountInput,
  parseOtpAuthUri,
} from "../parser/otpauth.js";
import { parseMigrationUri } from "../parser/migration.js";
import { decodeQrFromPng } from "../qr/decode.js";
import { renderQrSvg } from "../qr/encode.js";
import {
  generateHOTP,
  generateTOTP,
  verifyTOTP,
} from "../core/otp.js";
import { base32Decode } from "../core/base32.js";
import {
  AccountNotFoundError,
  InvalidParameterError,
} from "../core/errors.js";
import { normalizeSecret } from "../storage/account.js";
import { VaultManager, type VaultManagerOptions } from "../storage/vault.js";
import {
  type NewAccountInput,
  type OtpAccount,
} from "../storage/account.js";
import { LiveCodeTicker } from "./ticker.js";

/** Servis liste çıktısı; secret isteğe bağlı gizlenebilir. */
export type AccountView = OtpAccount | Omit<OtpAccount, "secret">;

export interface ListAccountsOptions {
  hideSecrets?: boolean;
}

export type AddAccountInput = NewAccountInput | string;
export type BackupImportMode = "merge" | "replace";

/** Üretilen kod sonucu; TOTP kalan süre taşır, HOTP tek kullanımlıktır. */
export type CodeResult =
  | { type: "totp"; code: string; remainingSeconds: number; periodSeconds: number }
  | { type: "hotp"; code: string };

/** HOTP doğrulamada RFC 4226 §7.4 uyumlu resync penceresi. */
export const HOTP_LOOKAHEAD = 10;

/** `importMigration` sonucu. */
export interface MigrationImportResult {
  /** Kasaya eklenen hesap sayısı (tekrar hariç). */
  added: number;
  /** MD5 algoritmalı olduğu için atlanan hesap sayısı. */
  skippedMd5: number;
  /** Gizli anahtar veya adı eksik olduğu için atlanan hesap sayısı. */
  skippedInvalid: number;
}

/** Geçici backup dosyası izinleri: yalnız sahip okuyup yazabilir. */
const BACKUP_FILE_MODE = 0o600;

/**
 * fiotp uygulamasının programatik servis facade'i.
 * Storage, URI, QR ve OTP katmanlarını tek bir güvenli API altında birleştirir.
 */
export class FiotpService {
  private readonly ticker: LiveCodeTicker;

  private constructor(private readonly vault: VaultManager) {
    this.ticker = new LiveCodeTicker((id) => this.requireAccount(id));
  }

  public static async create(
    path: string,
    masterPassword: string,
    options?: VaultManagerOptions,
  ): Promise<FiotpService> {
    return new FiotpService(await VaultManager.create(path, masterPassword, options));
  }

  public static async open(
    path: string,
    masterPassword: string,
    options?: VaultManagerOptions,
  ): Promise<FiotpService> {
    return new FiotpService(await VaultManager.open(path, masterPassword, options));
  }

  /**
   * Bozulmuş bir kasa dosyasını önceki iyi sürümden (`<kasa>.bak`) kurtarır.
   */
  public static async restoreBackup(path: string): Promise<void> {
    await VaultManager.restoreBackup(path);
  }

  public get isUnlocked(): boolean {
    return this.vault.isUnlocked;
  }

  public addAccount(input: AddAccountInput): OtpAccount {
    return this.vault.addAccount(
      typeof input === "string"
        ? otpAuthToAccountInput(parseOtpAuthUri(input))
        : input,
    );
  }

  public addAccountFromQr(pngBytes: Uint8Array): OtpAccount {
    return this.addAccount(decodeQrFromPng(pngBytes));
  }

  public listAccounts(): ReadonlyArray<OtpAccount>;
  public listAccounts(options: { hideSecrets: true }): ReadonlyArray<Omit<OtpAccount, "secret">>;
  public listAccounts(options?: ListAccountsOptions): ReadonlyArray<AccountView> {
    const accounts = this.vault.listAccounts();
    if (!options?.hideSecrets) return accounts;
    return accounts.map(({ secret: _secret, ...account }) => account);
  }

  public removeAccount(id: string): boolean {
    this.ticker.stop();
    return this.vault.removeAccount(id);
  }

  /**
   * Hesap için güncel tek kullanımlık kodu üretir.
   * TOTP hesapları kalan süre bilgisiyle döner; HOTP kodu tek seferliktir.
   */
  public getCode(id: string): CodeResult {
    const account = this.requireAccount(id);
    if (account.type === "hotp") {
      const code = generateHOTP(
        base32Decode(account.secret),
        BigInt(account.counter ?? 0),
        { algorithm: account.algorithm, digits: account.digits },
      );
      return { type: "hotp", code };
    }
    const totp = generateTOTP(account.secret, undefined, {
      algorithm: account.algorithm,
      digits: account.digits,
      period: account.period,
    });
    return { type: "totp", ...totp };
  }

  /**
   * Kullanıcının girdiği kodu doğrular.
   *
   * HOTP hesaplarında RFC 4226 §7.4 resync penceresi (10 sayaç) taranır;
   * eşleşme bulunursa sayaç eşleşen değerin bir sonrasına ilerletilir ve
   * kasa otomatik olarak kaydedilir.
   */
  public async verifyCode(id: string, token: string): Promise<boolean> {
    const account = this.requireAccount(id);

    if (account.type === "totp") {
      return verifyTOTP(account.secret, token, {
        algorithm: account.algorithm,
        digits: account.digits,
        period: account.period,
      });
    }

    if (!/^\d+$/.test(token) || token.length !== account.digits) {
      return false;
    }

    const secretKey = base32Decode(account.secret);
    const start = BigInt(account.counter ?? 0);
    for (let offset = 0n; offset < BigInt(HOTP_LOOKAHEAD); offset++) {
      const candidate = generateHOTP(secretKey, start + offset, {
        algorithm: account.algorithm,
        digits: account.digits,
      });
      const a = Buffer.from(candidate, "utf8");
      const b = Buffer.from(token, "utf8");
      if (a.length === b.length && timingSafeEqual(a, b)) {
        this.vault.updateAccount(id, { counter: Number(start + offset + 1n) });
        await this.vault.save();
        return true;
      }
    }
    return false;
  }

  /**
   * Hesabı saniyelik canlı kod akışına abone eder.
   *
   * @throws {InvalidParameterError} HOTP hesapları zamana dayalı olmadığı için.
   */
  public subscribe(id: string, listener: Parameters<LiveCodeTicker["subscribe"]>[1]): () => void {
    const account = this.requireAccount(id);
    if (account.type === "hotp") {
      throw new InvalidParameterError(
        "subscribe",
        "HOTP hesapları canlı akış desteklemez",
      );
    }
    return this.ticker.subscribe(id, listener);
  }

  public async getQrSvg(id: string): Promise<string> {
    return renderQrSvg(buildOtpAuthUri(this.requireAccount(id)));
  }

  public async save(): Promise<void> {
    await this.vault.save();
  }

  /**
   * Master parolayı değiştirir ve kasayı yeni anahtarla yeniden şifreler.
   * Mevcut parola yeniden doğrulanır; yanlışsa `WrongMasterPasswordError`.
   */
  public async changeMasterPassword(
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    await this.vault.changeMasterPassword(currentPassword, newPassword);
  }

  /** Kasanın güncel, zaten şifreli JSON içeriğini dışa aktarır. */
  public async exportBackup(): Promise<string> {
    await this.vault.save();
    return readFile(this.vault.path, "utf8");
  }

  /** Başka bir şifreli kasadan hesapları merge veya replace ile içe aktarır. */
  public async importBackup(
    backupJson: string,
    backupPassword: string,
    mode: BackupImportMode = "merge",
  ): Promise<number> {
    if (mode !== "merge" && mode !== "replace") {
      throw new InvalidParameterError("mode", '"merge" veya "replace" olmalıdır');
    }

    const directory = await mkdtemp(join(tmpdir(), "fiotp-backup-"));
    const backupPath = join(directory, "backup.json");
    try {
      await writeFile(backupPath, backupJson, {
        encoding: "utf8",
        mode: BACKUP_FILE_MODE,
      });
      const backup = await VaultManager.open(backupPath, backupPassword, {
        autoLockMs: null,
      });
      const imported = backup.listAccounts();
      const existing = this.vault.listAccounts();

      if (mode === "replace") {
        for (const account of existing) this.vault.removeAccount(account.id);
      }

      const current = [...this.vault.listAccounts()];
      let added = 0;
      for (const account of imported) {
        const duplicate = current.some(
          (candidate) =>
            candidate.issuer === account.issuer &&
            candidate.account === account.account &&
            candidate.secret === account.secret,
        );
        if (!duplicate) {
          this.vault.addAccount(account);
          current.push(account);
          added++;
        }
      }
      backup.lock();
      await this.vault.save();
      return added;
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }

  /**
   * Google Authenticator aktarım URI'sinden (`otpauth-migration://`)
   * hesapları içe aktarır. Tekrarlar (issuer+account+secret) atlanır.
   *
   * @returns Eklenen hesap sayısı ve atlananların özeti.
   */
  public importMigration(uri: string): MigrationImportResult {
    const { accounts, skippedMd5, skippedInvalid } = parseMigrationUri(uri);
    const current = [...this.vault.listAccounts()];
    let added = 0;

    for (const input of accounts) {
      const normalisedSecret = normalizeSecret(input.secret);
      const duplicate = current.some(
        (candidate) =>
          candidate.issuer === (input.issuer ?? "") &&
          candidate.account === input.account &&
          candidate.secret === normalisedSecret,
      );
      if (!duplicate) {
        this.vault.addAccount(input);
        added++;
      }
    }

    return { added, skippedMd5, skippedInvalid };
  }

  public lock(): void {
    this.ticker.stop();
    this.vault.lock();
  }

  public get tickerRunning(): boolean {
    return this.ticker.isRunning;
  }

  private requireAccount(id: string): OtpAccount {
    const account = this.vault.listAccounts().find((candidate) => candidate.id === id);
    if (!account) {
      // listAccounts already enforces the locked-state error.
      throw new AccountNotFoundError(id);
    }
    return account;
  }
}
