import { access, chmod, copyFile, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { decrypt, encrypt } from "../core/cipher.js";
import {
  AccountNotFoundError,
  CorruptVaultError,
  DecryptionError,
  FiotpError,
  InvalidParameterError,
  VaultAlreadyExistsError,
  VaultLockedError,
  VaultNotFoundError,
  WeakMasterPasswordError,
  WrongMasterPasswordError,
} from "../core/errors.js";
import {
  DEFAULT_PBKDF2_ITERATIONS,
  deriveKey,
  generateSalt,
} from "../core/kdf.js";
import {
  accountFromJSON,
  accountToJSON,
  createAccount,
  type NewAccountInput,
  type OtpAccount,
} from "./account.js";
import {
  fromBase64,
  parseVaultFile,
  payloadFromB64,
  payloadToB64,
  serializeVaultFile,
  toBase64,
  VAULT_FORMAT,
  VAULT_VERSION,
  type EncryptedPayloadB64,
  type VaultFile,
  type VaultKdfParams,
} from "./serialization.js";
import { LoginThrottle } from "./loginThrottle.js";

/** Otomatik kilit için varsayılan süre: 5 dakika. */
export const DEFAULT_AUTO_LOCK_MS = 300_000;

/** Master parolanın doğru olduğunu kanıtlayan sabit doğrulayıcı düz metin. */
const VERIFIER_PLAINTEXT = "fiotp-vault-verify";

/** Şifreli kasa dosyası bayt uzunluğu (Şema sabiti: 16 bayt). */
const SALT_LENGTH_BYTES = 16;

/** Tüm kasalar arasında paylaşılan varsayılan parola deneme sınırlayıcı. */
const defaultLoginThrottle = new LoginThrottle();

/** `VaultManager` yapılandırma seçenekleri. */
export interface VaultManagerOptions {
  /**
   * Hareketsizlik sonrası otomatik kilit süresi (milisaniye).
   * Varsayılan: 300000 (5 dakika). Devre dışı bırakmak için `null`.
   */
  autoLockMs?: number | null;

  /** Yeni kasa oluştururken PBKDF2 iterasyon sayısı (varsayılan: 600.000). */
  iterations?: number;

  /**
   * Başarısız parola denemelerini sınırlayan mekanizma. Varsayılan olarak
   * süreç genelinde paylaşılan bir örnek kullanılır.
   */
  loginThrottle?: LoginThrottle;
}

/**
 * Şifreli yerel kasa yöneticisi.
 *
 * Tüm gizli hesap verileri AES-256-GCM ile tek bir şifreli blokta saklanır;
 * diskte asla düz metin bulunmaz. Master parola, kasa açılırken PBKDF2 ile
 * anahtara dönüştürülür ve anahtar yalnızca kasa açıkken bellekte tutulur.
 * Hareketsizlik durumunda kasa kendini otomatik olarak kilitler.
 */
export class VaultManager {
  private key: Uint8Array | null = null;
  private accounts: OtpAccount[] = [];
  private autoLockTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly autoLockMs: number | null;
  private kdfParams: VaultKdfParams;
  private verifier: EncryptedPayloadB64;
  private writeQueue: Promise<unknown> = Promise.resolve();

  private constructor(
    private readonly filePath: string,
    autoLockMs: number | null,
    key: Uint8Array,
    accounts: OtpAccount[],
    kdfParams: VaultKdfParams,
    verifier: EncryptedPayloadB64,
    private readonly loginThrottle: LoginThrottle,
  ) {
    this.autoLockMs = autoLockMs;
    this.key = key;
    this.accounts = accounts;
    this.kdfParams = kdfParams;
    this.verifier = verifier;
    this.touch();
  }

  /**
   * Yeni bir kasa oluşturur ve kilitli olarak açar (boş hesap listesiyle).
   *
   * @param filePath Kasa dosyasının yolu (çağırıcı belirler).
   * @param masterPassword Kasa master parolası.
   * @param options Otomatik kilit ve KDF seçenekleri.
   * @returns Açılmış `VaultManager` örneği.
   * @throws {VaultAlreadyExistsError} Yolda zaten dosya varsa.
   * @throws {WeakMasterPasswordError} Parola 8 karakterden kısaysa.
   */
  public static async create(
    filePath: string,
    masterPassword: string,
    options: VaultManagerOptions = {},
  ): Promise<VaultManager> {
    const autoLockMs = normalizeAutoLock(options.autoLockMs);
    const iterations = options.iterations ?? DEFAULT_PBKDF2_ITERATIONS;

    if (await fileExists(filePath)) {
      throw new VaultAlreadyExistsError(filePath);
    }

    const salt = generateSalt();
    const key = await deriveKey(masterPassword, salt, iterations);

    const verifier = encrypt(
      new TextEncoder().encode(VERIFIER_PLAINTEXT),
      key,
    );
    const data = encrypt(new TextEncoder().encode("[]"), key);

    const file: VaultFile = {
      format: VAULT_FORMAT,
      version: VAULT_VERSION,
      kdf: {
        algorithm: "PBKDF2-SHA256",
        iterations,
        salt: toBase64(salt),
      },
      verifier: payloadToB64(verifier),
      data: payloadToB64(data),
    };

    await atomicWriteFile(filePath, serializeVaultFile(file));

    return new VaultManager(
      filePath,
      autoLockMs,
      key,
      [],
      file.kdf,
      file.verifier,
      options.loginThrottle ?? defaultLoginThrottle,
    );
  }

  /**
   * Mevcut bir kasayı master parola ile açar.
   *
   * Parola doğrulaması, PBKDF2 ile türetilen anahtarla kasadaki doğrulayıcı
   * bloğunun AES-GCM kimlik etiketi üzerinden yapılır; parolanın hiçbir
   * türevi dosyada saklanmaz.
   *
   * @param filePath Kasa dosyasının yolu.
   * @param masterPassword Kasa master parolası.
   * @param options Otomatik kilit seçenekleri.
   * @returns Açılmış `VaultManager` örneği.
   * @throws {VaultNotFoundError} Dosya yoksa.
   * @throws {WrongMasterPasswordError} Parola yanlışsa.
   * @throws {CorruptVaultError} Dosya bozuksa veya şema uyuşmuyorsa.
   */
  public static async open(
    filePath: string,
    masterPassword: string,
    options: VaultManagerOptions = {},
  ): Promise<VaultManager> {
    const autoLockMs = normalizeAutoLock(options.autoLockMs);
    const loginThrottle = options.loginThrottle ?? defaultLoginThrottle;

    if (!(await fileExists(filePath))) {
      throw new VaultNotFoundError(filePath);
    }

    loginThrottle.check(filePath);

    let raw: string;
    try {
      raw = await readFile(filePath, "utf8");
    } catch {
      throw new CorruptVaultError("dosya okunamadı");
    }

    const file = parseVaultFile(raw);

    const salt = fromBase64(file.kdf.salt);
    if (salt.length !== SALT_LENGTH_BYTES) {
      throw new CorruptVaultError("KDF tuzunun uzunluğu geçersiz");
    }

    const key = await deriveKey(masterPassword, salt, file.kdf.iterations);

    try {
      const verifierPlain = decrypt(payloadFromB64(file.verifier), key);
      if (new TextDecoder().decode(verifierPlain) !== VERIFIER_PLAINTEXT) {
        throw new DecryptionError("doğrulayıcı düz metni uyuşmuyor");
      }
    } catch (error) {
      if (error instanceof DecryptionError) {
        loginThrottle.recordFailure(filePath);
        throw new WrongMasterPasswordError();
      }
      throw error;
    }

    let accounts: OtpAccount[];
    try {
      const dataPlain = decrypt(payloadFromB64(file.data), key);
      accounts = parseAccounts(new TextDecoder().decode(dataPlain));
    } catch (error) {
      if (error instanceof DecryptionError) {
        throw new CorruptVaultError("veri bölümü çözülemedi");
      }
      throw error;
    }

    loginThrottle.recordSuccess(filePath);

    return new VaultManager(
      filePath,
      autoLockMs,
      key,
      accounts,
      file.kdf,
      file.verifier,
      loginThrottle,
    );
  }

  /** Kasa şu anda açık mı? */
  public get isUnlocked(): boolean {
    return this.key !== null;
  }

  /**
   * Kasa dosyasını, önceki iyi sürümden (`<kasa>.bak`) kurtarır.
   *
   * `save()` her başarılı yazmadan önce mevcut dosyayı yedeklediğinden,
   * kasa dosyası bozulursa (ör. disk hatası, elle kurcalama) son iyi sürüm
   * geri yüklenebilir.
   *
   * @param filePath Kurtarılacak kasa dosyasının yolu.
   * @throws {VaultNotFoundError} Yedek dosyası mevcut değilse.
   */
  public static async restoreBackup(filePath: string): Promise<void> {
    const backupPath = `${filePath}${BACKUP_SUFFIX}`;
    if (!(await fileExists(backupPath))) {
      throw new VaultNotFoundError(backupPath);
    }
    await copyFile(backupPath, filePath);
    await chmod(filePath, FILE_MODE);
  }

  /** Kasa dosyasının yolu. */
  public get path(): string {
    return this.filePath;
  }

  /**
   * Kasa içeriği okunabilir kopyalarla listeler.
   * Dönen nesneleri değiştirmek kasayı etkilemez.
   */
  public listAccounts(): ReadonlyArray<OtpAccount> {
    this.requireUnlocked();
    this.touch();
    return this.accounts.map((account) => ({ ...account }));
  }

  /**
   * Kasaya yeni bir hesap ekler. Kalıcı olması için `save()` çağrılmalıdır.
   *
   * @throws {VaultLockedError} Kasa kilitliyse.
   * @throws {InvalidBase32SecretError} Gizli anahtar geçersizse.
   * @throws {InvalidParameterError} Diğer alanlar geçersizse.
   */
  public addAccount(input: NewAccountInput): OtpAccount {
    this.requireUnlocked();
    this.touch();
    const account = createAccount(input);
    this.accounts.push(account);
    return { ...account };
  }

  /**
   * Mevcut hesabın alanlarını günceller (kimlik ve oluşturma zamanı korunur).
   *
   * @param id Güncellenecek hesabın kimliği.
   * @param patch Değiştirilecek alanlar.
   * @throws {VaultLockedError} Kasa kilitliyse.
   * @throws {AccountNotFoundError} Hesap yoksa.
   */
  public updateAccount(
    id: string,
    patch: Partial<NewAccountInput>,
  ): OtpAccount {
    this.requireUnlocked();
    this.touch();

    const index = this.accounts.findIndex((a) => a.id === id);
    if (index === -1) {
      throw new AccountNotFoundError(id);
    }
    const existing = this.accounts[index]!;

    const merged = createAccount({
      type: existing.type,
      issuer: patch.issuer ?? existing.issuer,
      account: patch.account ?? existing.account,
      secret: patch.secret ?? existing.secret,
      algorithm: patch.algorithm ?? existing.algorithm,
      digits: patch.digits ?? existing.digits,
      period: patch.period ?? existing.period,
      counter: patch.counter ?? existing.counter,
    });

    const updated: OtpAccount = {
      ...merged,
      id: existing.id,
      createdAt: existing.createdAt,
    };
    this.accounts[index] = updated;
    return { ...updated };
  }

  /**
   * Hesabı kasadan kaldırır. Kalıcı olması için `save()` çağrılmalıdır.
   *
   * @returns Hesap kaldırıldıysa `true`, zaten yoksa `false`.
   * @throws {VaultLockedError} Kasa kilitliyse.
   */
  public removeAccount(id: string): boolean {
    this.requireUnlocked();
    this.touch();

    const index = this.accounts.findIndex((a) => a.id === id);
    if (index === -1) {
      return false;
    }
    this.accounts.splice(index, 1);
    return true;
  }

  /**
   * Kasanın güncel içeriğini diske yazar.
   * Veriler yeniden şifrelenir (yeni IV) ve yazma atomiktir: dosya
   * yarısı yazılmış durumda asla bırakılmaz.
   *
   * @throws {VaultLockedError} Kasa kilitliyse.
   * @throws {CorruptVaultError} Yazma başarısızsa.
   */
  public async save(): Promise<void> {
    return this.enqueue(async () => {
      const key = this.requireUnlocked();

      const dataPlain = JSON.stringify(this.accounts.map(accountToJSON));
      const data = encrypt(new TextEncoder().encode(dataPlain), key);

      const file: VaultFile = {
        format: VAULT_FORMAT,
        version: VAULT_VERSION,
        kdf: this.kdfParams,
        verifier: this.verifier,
        data: payloadToB64(data),
      };

      try {
        await atomicWriteFile(this.filePath, serializeVaultFile(file));
      } catch {
        throw new CorruptVaultError("kasa dosyasına yazılamadı");
      }

      this.touch();
    });
  }

  /**
   * Master parolayı değiştirir ve tüm kasayı yeni anahtarla yeniden şifreler.
   *
   * Kasa zaten açık olsa bile mevcut parola yeniden doğrulanır; böylece
   * kilidi açık bırakılmış bir oturumda yetkisiz parola değişimi engellenir.
   * Yeni tuz üretilir, doğrulayıcı ve veri blokları yeni anahtarla
   * şifrelenir ve dosya atomik olarak yazılır. Eski anahtar bellekten
   * sıfırlanır.
   *
   * @param currentPassword Mevcut master parola (yeniden doğrulanır).
   * @param newPassword Yeni master parola.
   * @throws {VaultLockedError} Kasa kilitliyse.
   * @throws {WrongMasterPasswordError} Mevcut parola yanlışsa.
   * @throws {WeakMasterPasswordError} Yeni parola çok zayıfsa.
   */
  public async changeMasterPassword(
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    return this.enqueue(async () => {
      const currentKey = this.requireUnlocked();
      this.loginThrottle.check(this.filePath);

      const salt = fromBase64(this.kdfParams.salt);
      let derivedCurrent: Uint8Array;
      try {
        derivedCurrent = await deriveKey(
          currentPassword,
          salt,
          this.kdfParams.iterations,
        );
      } catch (error) {
        // Zayıf parolayla oluşturulmuş kasa olamayacağından bu her zaman yanlış paroladır.
        if (
          error instanceof WeakMasterPasswordError ||
          error instanceof InvalidParameterError
        ) {
          this.loginThrottle.recordFailure(this.filePath);
          throw new WrongMasterPasswordError();
        }
        throw error;
      }

      try {
        const verifierPlain = decrypt(payloadFromB64(this.verifier), derivedCurrent);
        if (new TextDecoder().decode(verifierPlain) !== VERIFIER_PLAINTEXT) {
          throw new DecryptionError("doğrulayıcı düz metni uyuşmuyor");
        }
      } catch (error) {
        if (error instanceof DecryptionError) {
          this.loginThrottle.recordFailure(this.filePath);
          throw new WrongMasterPasswordError();
        }
        throw error;
      } finally {
        derivedCurrent.fill(0);
      }

      this.loginThrottle.recordSuccess(this.filePath);

      const newSalt = generateSalt();
      const newKey = await deriveKey(
        newPassword,
        newSalt,
        this.kdfParams.iterations,
      );

      try {
        const newVerifier = encrypt(
          new TextEncoder().encode(VERIFIER_PLAINTEXT),
          newKey,
        );
        const dataPlain = JSON.stringify(this.accounts.map(accountToJSON));
        const newData = encrypt(new TextEncoder().encode(dataPlain), newKey);

        const newKdfParams: VaultKdfParams = {
          ...this.kdfParams,
          salt: toBase64(newSalt),
        };
        const file: VaultFile = {
          format: VAULT_FORMAT,
          version: VAULT_VERSION,
          kdf: newKdfParams,
          verifier: payloadToB64(newVerifier),
          data: payloadToB64(newData),
        };

        await atomicWriteFile(this.filePath, serializeVaultFile(file));

        currentKey.fill(0);
        this.key = newKey;
        this.kdfParams = newKdfParams;
        this.verifier = payloadToB64(newVerifier);
      } catch (error) {
        newKey.fill(0);
        if (error instanceof FiotpError) {
          throw error;
        }
        throw new CorruptVaultError("kasa dosyasına yazılamadı");
      }

      this.touch();
    });
  }

  /**
   * Kasayı kilitler: anahtar baytları bellekte sıfırlanır ve tüm düz metin
   * hesap verileri düşürülür. (JavaScript dizeleri değişmez olduğundan
   * dize sıfırlama en iyi çabadır; referanslar düşürülür ve toplanır.)
   */
  public lock(): void {
    if (this.autoLockTimer !== null) {
      clearTimeout(this.autoLockTimer);
      this.autoLockTimer = null;
    }
    if (this.key !== null) {
      this.key.fill(0);
      this.key = null;
    }
    this.accounts = [];
  }

  /** Hareketsizlik sayacını sıfırlar. */
  private touch(): void {
    if (this.autoLockMs === null || this.key === null) {
      return;
    }
    if (this.autoLockTimer !== null) {
      clearTimeout(this.autoLockTimer);
    }
    this.autoLockTimer = setTimeout(() => this.lock(), this.autoLockMs);
    this.autoLockTimer.unref();
  }

  /** Kasanın açık olduğunu doğrular ve anahtarı döndürür. */
  private requireUnlocked(): Uint8Array {
    if (this.key === null) {
      throw new VaultLockedError();
    }
    return this.key;
  }

  /**
   * Yazma işlemlerini sıraya sokar; eşzamanlı `save()` ve
   * `changeMasterPassword()` çağrıları birbirini beklemeden dosyayı
   * yazmaya çalışmaz.
   */
  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.writeQueue.then(operation, operation);
    this.writeQueue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}

/** Doğrulanmış autoLockMs değerine dönüştürür. */
function normalizeAutoLock(
  autoLockMs: number | null | undefined,
): number | null {
  const value =
    autoLockMs === undefined ? DEFAULT_AUTO_LOCK_MS : autoLockMs;
  if (value !== null && (!Number.isInteger(value) || value < 1_000)) {
    throw new InvalidParameterError(
      "autoLockMs",
      "en az 1000 ms olan bir tam sayı veya null (devre dışı) olmalıdır",
    );
  }
  return value;
}

/** Dosyanın var olup olmadığını kontrol eder. */
async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

/** Kasa dosyası izinleri: yalnız sahip okuyup yazabilir. */
const FILE_MODE = 0o600;

/** Kasa dizini izinleri: yalnız sahip erişebilir. */
const DIR_MODE = 0o700;

/** Kasa yedek dosyası son eki: önceki iyi sürümü saklar. */
const BACKUP_SUFFIX = ".bak";

/**
 * Önce geçici dosyaya yazar, mevcut dosyayı yedekler ve atomik olarak
 * yeniden adlandırır. Böylece başarılı her yazmadan önceki son iyi sürüm
 * `<kasa>.bak` olarak saklanır.
 */
async function atomicWriteFile(
  path: string,
  contents: string,
): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: DIR_MODE });
  const tmpPath = `${path}.tmp`;
  await writeFile(tmpPath, contents, { encoding: "utf8", mode: FILE_MODE });
  await chmod(tmpPath, FILE_MODE);
  if (await fileExists(path)) {
    await copyFile(path, `${path}${BACKUP_SUFFIX}`);
    await chmod(`${path}${BACKUP_SUFFIX}`, FILE_MODE);
  }
  await rename(tmpPath, path);
}

/** Şifre çözülmüş hesap listesi JSON'unu doğrular ve ayrıştırır. */
function parseAccounts(json: string): OtpAccount[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new CorruptVaultError("hesap listesi geçerli JSON değil");
  }
  if (!Array.isArray(parsed)) {
    throw new CorruptVaultError("hesap listesi bir dizi değil");
  }
  return parsed.map((item) => accountFromJSON(item));
}
