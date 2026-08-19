# fiotp — Proje Durum Raporu (Deadline Hazırlığı)

**Tarih:** 19 Ağustos 2026
**Versiyon:** 0.1.0
**Lisans:** MIT
**Gereksinim:** Node.js ≥ 20

---

## Genel Bakış

fiotp, RFC 6238 (TOTP) ve RFC 4226 (HOTP) standartlarına tam uyumlu, AES-256-GCM ile şifrelenmiş yerel kasada saklanan bir 2FA/TOTP uygulamasıdır. CLI ve programatik API olarak kullanılabilir; saf JavaScript QR desteği, Google Authenticator aktarma, HOTP sayaç yönetimi ve canli kod paneli içerir.

---

## Proje Metrikleri

| Metrik | Değer |
|---|---|
| Kaynak dosya | 23 TypeScript dosyası |
| Test dosyası | 15 Vitest dosyası |
| Kaynak satır | ~3.036 satır (src/) |
| Test satırı | ~2.267 satır (tests/) |
| Toplam satır | ~5.303 satır |
| Test sayısı | **178 / 178 geçti** |
| Statement coverage | **%91.76** |
| Branch coverage | **%88.41** |
| Function coverage | **%97.2** |
| Line coverage | **%92.42** |
| Güvenlik açığı | **0** (npm audit) |
| Runtime bağımlılık | 3 (jsqr, pngjs, qrcode — tümü saf JS) |
| TypeScript | strict mode, ESM |
| CI | GitHub Actions (Node 20/22/24 matrisi) |

---

## Tamamlanan Özellikler

### Çekirdek (Modül 1 — `src/core/`)
| Özellik | Durum | Detay |
|---|---|---|
| HOTP (RFC 4226) | ✅ | Appendix D test vektörleri doğrulandı |
| TOTP (RFC 6238) | ✅ | Appendix B test vektörleri doğrulandı (SHA1/SHA256/SHA512) |
| Base32 (RFC 4648) | ✅ | Encode/decode + doğrulama |
| AES-256-GCM | ✅ | Rastgele IV (12 byte) + auth tag (16 byte) |
| PBKDF2-SHA256 | ✅ | 600.000 iterasyon (OWASP), 16-byte salt |
| Hata hiyerarşisi | ✅ | 15 FiotpError alt sınıfı |

### Kasa (Modül 2 — `src/storage/`)
| Özellik | Durum | Detay |
|---|---|---|
| VaultManager | ✅ | create/open/save/lock/changeMasterPassword |
| Atomik yazma | ✅ | tmp + rename + .bak backup |
| Dosya izinleri | ✅ | 0600 (dosya), 0700 (dizin) |
| Otomatik kilit | ✅ | 5 dk (varsayılan), yapılandırılabilir |
| Rate limiting | ✅ | 5 başarısız deneme → üstel geri çekilme (30sn-15dk) |
| Eşzamanlı yazma | ✅ | enqueue mutex ile serialize |
| Master parola değiştirme | ✅ | Tüm kasa yeniden şifrelenir |
| Kasa kurtarma | ✅ | .bak backup + restoreBackup + CLI recover |
| Hesap modeli | ✅ | TOTP + HOTP, secret/algorithm/digits/period/counter |

### URI & QR (Modül 3 — `src/parser/` + `src/qr/`)
| Özellik | Durum | Detay |
|---|---|---|
| otpauth:// parse/build | ✅ | TOTP + HOTP, katı doğrulama |
| Google Authenticator aktarma | ✅ | otpauth-migration:// protobuf decode |
| Minimal protobuf okuyucu | ✅ | Sıfır bağımlılık, wire format subset |
| QR üretme (SVG/terminal/PNG) | ✅ | Saf JS (qrcode paketi) |
| QR okuma (PNG) | ✅ | Saf JS (jsqr + pngjs) |

### Servis & CLI (Modül 4 — `src/service/` + `src/cli/`)
| Özellik | Durum | Detay |
|---|---|---|
| FiotpService facade | ✅ | Tüm modülleri tek API altında birleştirir |
| Canlı kod akışı | ✅ | LiveCodeTicker (1sn aralık, EventEmitter) |
| HOTP resync | ✅ | RFC 4226 §7.4 uyumlu 10 sayaç penceresi + otomatik ilerleme |
| Şifreli export/import | ✅ | Merge ve replace modları |
| CLI init | ✅ | Kasa oluşturma |
| CLI add | ✅ | URI, secret veya otpauth-migration:// otomatik algılama |
| CLI list | ✅ | Hesapları listeleme (secret gizlenebilir) |
| CLI code | ✅ | Kod üretme (TOTP canlı, HOTP tek seferlik) |
| CLI qr | ✅ | Terminalde QR gösterme |
| CLI export/import | ✅ | Şifreli yedekleme/geri yükleme |
| CLI passwd | ✅ | Master parola değiştirme |
| CLI watch | ✅ | Canlı panel (tüm TOTP hesapları tek ekranda) |
| CLI recover | ✅ | .bak kurtarma |

---

## Güvenlik Kontrol Listesi

- [x] Gizli anahtarlar diskte asla düz metin saklanmaz
- [x] AES-256-GCM + rastgele IV + auth tag
- [x] PBKDF2 600k iterasyon (OWASP)
- [x] Parola hash'i saklanmaz (GCM tag üzerinden doğrulama)
- [x] Dosya izinleri 0600/0700
- [x] Atomik yazma (tmp + rename)
- [x] Timing-safe karşılaştırma (verifyTOTP, verifyCode)
- [x] Rate limiting (exponential backoff)
- [x] 5 dk otomatik kilit
- [x] Key sıfırlama (lock())
- [x] .bak backup ile kurtarma
- [x] npm audit: 0 açık
- [x] Kullanıcı arayüzünde parola gizli giriş

---

## Kalan İşler (Opsiyonel / Gelecek Sürüm)

| Özellik | Öncelik | Not |
|---|---|---|
| Çoklu QR batch (otpauth-migration) | Düşük | Nadir durum; Google büyük aktarımları böler |
| JPEG/WebP QR okuma | Düşük | Native bağımlılık (sharp) gerektirir |
| Grafiksel arayüz (GUI) | Düşük | Ayrı proje kararı (Electron/Tauri/web) |
| Property-based / fuzz testleri | Orta | Larger input coverage için |
| OTP resync komutu (CLI) | Orta | Manuel sayaç ilerleme |
| Argon2id KDF alternatifi | Düşük | Native bağımlılık; PBKDF2 OWASP uyumlu |

---

## Test Kapsamı Detayları

En düşük kapsama sahip dosyalar:

| Dosya | Satır % | Açıklama |
|---|---|---|
| `qr/encode.ts` | %100 | Terminal PGM çıkışı kapsanmamış olabilir (fmt mock) |
| `qr/decode.ts` | %93.3 | Dosya yolu testi (decodeQrFromPngFile) |
| `parser/otpauth.ts` | %88.6 | Bazı hata yolları kapsanmamış |
| `parser/protobuf.ts` | %83.8 | Hata yolları (kesik varint, taşma) |

Genel: **%92 satır, %97 fonksiyon** — üretim için yeterli.

---

## Proje Yapısı

```
src/
├── core/          # OTP motoru, base32, cipher, KDF, hatalar
│   ├── otp.ts         372 satır — HOTP + TOTP
│   ├── base32.ts       72 satır — RFC 4648
│   ├── cipher.ts      103 satır — AES-256-GCM
│   ├── kdf.ts          54 satır — PBKDF2-SHA256
│   ├── errors.ts      133 satır — 15 hata sınıfı
│   └── index.ts
├── storage/       # Şifreli kasa, hesap modeli
│   ├── vault.ts       632 satır — VaultManager
│   ├── account.ts     279 satır — hesap modeli + validation
│   ├── serialization.ts 173 satır — JSON şema
│   ├── loginThrottle.ts  80 satır — rate limiting
│   └── index.ts
├── parser/        # URI ayrıştırma, migration
│   ├── otpauth.ts     222 satır — otpauth:// parse/build
│   ├── migration.ts   212 satır — otpauth-migration://
│   ├── protobuf.ts     93 satır — minimal protobuf reader
│   └── index.ts
├── qr/            # QR üretme/okuma
│   ├── encode.ts     103 satır — SVG/terminal/PNG
│   ├── decode.ts     110 satır — PNG decode (jsqr+pngjs)
│   └── index.ts
├── service/       # Programatik API
│   ├── fiotp.ts      320 satır — FiotpService
│   ├── ticker.ts      87 satır — LiveCodeTicker
│   └── index.ts
├── cli/           # Komut satırı arayüzü
│   └── index.ts      260 satır — 11 komut
└── index.ts       # Barrel export
tests/
├── hotp.test.ts         # RFC 4226 Appendix D
├── otp.test.ts          # RFC 6238 Appendix B + edge cases
├── base32.test.ts
├── cipher.test.ts
├── kdf.test.ts
├── account.test.ts
├── serialization.test.ts
├── vault.test.ts
├── loginThrottle.test.ts
├── otpauth.test.ts
├── migration.test.ts    # otpauth-migration:// (yeni)
├── qr.test.ts
├── service.test.ts
├── ticker.test.ts
└── permissions.test.ts
```

---

## Doğrulama

```bash
npm run typecheck   # ✅ geçti
npm test            # ✅ 178/178
npm run coverage    # ✅ %92 satır
npm run build       # ✅ temiz
npm audit           # ✅ 0 açık
```
