import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";
import { DecryptionError, InvalidParameterError } from "./errors.js";

/** AES-256-GCM şifreleme sonucunun ham bileşenleri. */
export interface EncryptedPayload {
  /** 12 baytlık rastgele başlangıç vektörü (her işlemde yeniden üretilir). */
  iv: Uint8Array;
  /** Şifrelenmiş içerik (gizli metin ile aynı uzunlukta). */
  ciphertext: Uint8Array;
  /** 16 baytlık GCM kimlik doğrulama etiketi (bütünlük koruması). */
  authTag: Uint8Array;
}

const IV_LENGTH_BYTES = 12;
const KEY_LENGTH_BYTES = 32;
const AUTH_TAG_LENGTH_BYTES = 16;

/**
 * Veriyi AES-256-GCM ile şifreler.
 *
 * GCM, aynı veri ve anahtarla her seferinde farklı sonuç üreten (rastgele IV)
 * kimlik doğrulamalı şifreleme sağlar: veri hem gizli kalır hem de kurcalanamaz.
 *
 * @param plaintext Şifrelenecek veri.
 * @param key 32 baytluk anahtar (bkz. `deriveKey`).
 * @returns IV, şifreli metin ve kimlik doğrulama etiketi.
 * @throws {InvalidParameterError} Anahtar uzunluğu 32 bayt değilse.
 */
export function encrypt(plaintext: Uint8Array, key: Uint8Array): EncryptedPayload {
  assertKeyLength(key);

  const iv = randomBytes(IV_LENGTH_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return {
    iv: new Uint8Array(iv),
    ciphertext: new Uint8Array(ciphertext),
    authTag: new Uint8Array(authTag),
  };
}

/**
 * AES-256-GCM ile şifrelenmiş veriyi çözer.
 *
 * @param payload `encrypt` çıktısı.
 * @param key Şifrelemede kullanılan 32 baytluk anahtar.
 * @returns Çözülen düz metin.
 * @throws {InvalidParameterError} Anahtar uzunluğu hatalıysa.
 * @throws {DecryptionError} Anahtar yanlışsa, veri bozuksa veya etiket doğrulanamazsa.
 */
export function decrypt(
  payload: EncryptedPayload,
  key: Uint8Array,
): Uint8Array {
  assertKeyLength(key);

  if (payload.iv.length !== IV_LENGTH_BYTES) {
    throw new DecryptionError(`IV ${IV_LENGTH_BYTES} bayt olmalıdır`);
  }
  if (payload.authTag.length !== AUTH_TAG_LENGTH_BYTES) {
    throw new DecryptionError(
      `kimlik doğrulama etiketi ${AUTH_TAG_LENGTH_BYTES} bayt olmalıdır`,
    );
  }

  try {
    const decipher = createDecipheriv("aes-256-gcm", key, payload.iv);
    decipher.setAuthTag(payload.authTag);
    const plaintext = Buffer.concat([
      decipher.update(payload.ciphertext),
      decipher.final(),
    ]);
    return new Uint8Array(plaintext);
  } catch {
    throw new DecryptionError(
      "anahtar yanlış veya veri bozuk/kurcalanmış olabilir",
    );
  }
}

function assertKeyLength(key: Uint8Array): void {
  if (key.length !== KEY_LENGTH_BYTES) {
    throw new InvalidParameterError(
      "key",
      `anahtar tam ${KEY_LENGTH_BYTES} bayt olmalıdır (alen: ${key.length})`,
    );
  }
}
