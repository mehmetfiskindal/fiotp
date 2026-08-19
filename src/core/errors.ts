/**
 * fiotp temel hata sınıfı.
 * Tüm modül özel hataları bu sınıftan türer; böylece üst katmanlar
 * `instanceof FiotpError` ile bilinen hataları, diğer beklenmedik
 * hatalardan ayırabilir.
 */
export class FiotpError extends Error {
  public constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message);
    this.name = new.target.name;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Base32 gizli anahtarı çözülemediğinde fırlatılır. */
export class InvalidBase32SecretError extends FiotpError {
  public constructor(detail: string) {
    super(`Geçersiz base32 gizli anahtarı: ${detail}`, "INVALID_BASE32_SECRET");
  }
}

/** Fonksiyona verilen parametre geçersiz olduğunda fırlatılır. */
export class InvalidParameterError extends FiotpError {
  public constructor(paramName: string, detail: string) {
    super(
      `Geçersiz parametre "${paramName}": ${detail}`,
      "INVALID_PARAMETER",
    );
  }
}

/** Şifreli veri çözülemediğinde (yanlış anahtar / bozuk veri / kurcalama) fırlatılır. */
export class DecryptionError extends FiotpError {
  public constructor(detail: string) {
    super(`Şifre çözme başarısız: ${detail}`, "DECRYPTION_FAILED");
  }
}

/** Master parola çok zayıf olduğunda fırlatılır. */
export class WeakMasterPasswordError extends FiotpError {
  public constructor() {
    super(
      "Master parola en az 8 karakter uzunluğunda olmalıdır.",
      "WEAK_MASTER_PASSWORD",
    );
  }
}

/** Kasa açılırken master parola yanlış olduğunda fırlatılır. */
export class WrongMasterPasswordError extends FiotpError {
  public constructor() {
    super(
      "Master parola hatalı veya kasa dosyası bozuk.",
      "WRONG_MASTER_PASSWORD",
    );
  }
}

/** Kasa kilitliyken işlem yapılmak istendiğinde fırlatılır. */
export class VaultLockedError extends FiotpError {
  public constructor() {
    super(
      "Kasa kilitli: bu işlem için önce kasayı master parolayla açın.",
      "VAULT_LOCKED",
    );
  }
}

/** Kasa dosyası okunamıyor veya içeriği geçersiz olduğunda fırlatılır. */
export class CorruptVaultError extends FiotpError {
  public constructor(detail: string) {
    super(`Kasa dosyası bozuk: ${detail}`, "CORRUPT_VAULT");
  }
}

/** Var olmayan bir kasa dosyası açılmak istendiğinde fırlatılır. */
export class VaultNotFoundError extends FiotpError {
  public constructor(path: string) {
    super(`Kasa dosyası bulunamadı: ${path}`, "VAULT_NOT_FOUND");
  }
}

/** Zaten mevcut bir kasa dosyası yeniden oluşturulmak istendiğinde fırlatılır. */
export class VaultAlreadyExistsError extends FiotpError {
  public constructor(path: string) {
    super(`Bu yolda zaten bir kasa var: ${path}`, "VAULT_ALREADY_EXISTS");
  }
}

/** Belirtilen kimliğe sahip hesap bulunamadığında fırlatılır. */
export class AccountNotFoundError extends FiotpError {
  public constructor(id: string) {
    super(`Hesap bulunamadı: ${id}`, "ACCOUNT_NOT_FOUND");
  }
}

/** otpauth URI biçimi veya parametreleri geçersiz olduğunda fırlatılır. */
export class InvalidOtpAuthUriError extends FiotpError {
  public constructor(detail: string) {
    super(`Geçersiz otpauth URI: ${detail}`, "INVALID_OTPAUTH_URI");
  }
}

/** QR kodu okunamadığında veya geçersiz görüntü verildiğinde fırlatılır. */
export class QrDecodeError extends FiotpError {
  public constructor(detail: string) {
    super(`QR kodu çözülemedi: ${detail}`, "QR_DECODE_FAILED");
  }
}

/** Çok fazla başarısız parola denemesi sonrası geçici kilit uygulanır. */
export class TooManyAttemptsError extends FiotpError {
  public constructor(public readonly retryAfterMs: number) {
    const seconds = Math.ceil(retryAfterMs / 1000);
    super(
      `Çok fazla başarısız deneme. ${seconds} saniye sonra tekrar deneyin.`,
      "TOO_MANY_ATTEMPTS",
    );
  }
}

/** Google Authenticator aktarım (otpauth-migration) verisi geçersiz olduğunda fırlatılır. */
export class InvalidMigrationError extends FiotpError {
  public constructor(detail: string) {
    super(
      `Geçersiz otpauth-migration verisi: ${detail}`,
      "INVALID_MIGRATION",
    );
  }
}
