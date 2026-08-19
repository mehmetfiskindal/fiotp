# fiotp

Hafif ve güvenli bir İki Faktörlü Kimlik Doğrulama (2FA/TOTP) uygulaması. RFC 6238 (TOTP) ve RFC 4226 (HOTP) standartlarına tam uyumlu kod üretimi, AES-256-GCM ile şifrelenmiş yerel kasa, `otpauth://` URI ayrıştırma, QR kod okuma/görüntüleme ve şifreli JSON yedekleme.

- **Sıfır runtime bağımlılık istemez**: kriptografi tamamen Node.js yerleşik `crypto` modülüyle yapılır (yalnız QR için hafif saf-JS paketler kullanılır).
- **TypeScript** ile tip korumalı, modüler ve test edilmiş.
- **CLI + programatik API** olarak kullanılabilir.

## İçindekiler

- [Özellikler](#özellikler)
- [Kurulum](#kurulum)
- [CLI Kullanımı](#cli-kullanımı)
  - [İlk kullanım (kasa oluşturma)](#ilk-kullanım-kasa-oluşturma)
  - [Hesap ekleme](#hesap-ekleme)
  - [Hesapları listeleme](#hesapları-listeleme)
  - [Kod üretme](#kod-üretme)
  - [QR gösterme](#qr-gösterme)
  - [Yedekleme](#yedekleme)
  - [Master parola değiştirme](#master-parola-değiştirme)
- [Programatik API](#programatik-api)
- [Güvenlik Modeli](#güvenlik-modeli)
- [Proje Yapısı](#proje-yapısı)
- [Geliştirme](#geliştirme)
- [Sınırlamalar](#sınırlamalar)

## Özellikler

- RFC 4226 / RFC 6238 uyumlu **HOTP ve TOTP** (SHA-1, SHA-256, SHA-512; 6-10 hane; özel pencere süresi)
- **AES-256-GCM** ile şifrelenmiş yerel kasa; diskte asla düz metin saklanmaz
- **PBKDF2-HMAC-SHA256** (600.000 iterasyon, OWASP önerisi) anahtar türetme
- Master parola doğrulaması GCM kimlik doğrulama etiketi üzerinden yapılır — parola karması saklanmaz
- `otpauth://totp/...` ve `otpauth://hotp/...` URI ayrıştırma/üretme, katı doğrulama
- **Google Authenticator aktarım** (`otpauth-migration://`) ile toplu hesap içe aktarma (TOTP/HOTP, SHA-256/512 destekli; MD5 hesapları otomatik atlanır)
- QR kod üretme (SVG/terminal/PNG) ve PNG okuma (saf JS)
- Canlı kod akışı: her saniye `{ code, remainingSeconds }` yayını
- HOTP doğrulamada RFC 4226 §7.4 uyumlu **resync penceresi** (10 sayaç) ve otomatik sayaç ilerleme
- Şifreli JSON **export/import** (merge / replace)
- Master parola değiştirme (tüm kasa yeni anahtarla yeniden şifrelenir)
- Otomatik **kasa yedekleme** (`<kasa>.bak`) ve `recover` ile kurtarma
- Kasa dosyaları **0600** izniyle, dizinler **0700** izniyle yazılır; yazma atomiktir (tmp + rename)
- 5 dakika hareketsizlikte **otomatik kilit** (ayarlanabilir)
- Başarısız parola denemelerinde **üstel geri çekilme** (rate limiting)
- Eşzamanlı yazma işlemleri (save / parola değiştirme) kuyruğa alınır
- Farklılık testleri RFC resmî test vektörleriyle doğrulanır

## Kurulum

Gereksinim: **Node.js ≥ 20**

```bash
npm install
npm run build          # dist/ klasörüne derle
```

CLI'yı global olarak kullanmak için:

```bash
npm link               # `fiotp` komutu terminale gelir
```

CLI'yı linklemeden de kullanabilirsiniz:

```bash
node dist/cli/index.js list /path/to/kasa.json
```

## CLI Kullanımı

```
fiotp init <kasa>
fiotp add <kasa> [otpauth-uri|secret]
fiotp list <kasa>
fiotp code <kasa> [hesap-id|account]
fiotp qr <kasa> <hesap-id|account>
fiotp export <kasa> <yedek.json>
fiotp import <kasa> <yedek.json>
fiotp passwd <kasa>
fiotp watch <kasa>
fiotp recover <kasa>
```

Parolalar etkileşimli olarak ekrana yazdırılmadan sorulur. Betik/senaryolar için ortam değişkenleri:

- `FIOTP_PASSWORD` — kasayı açmak için mevcut master parola
- `FIOTP_NEW_PASSWORD` — yalnız `passwd` komutunda yeni parola

> **Not:** `FIOTP_PASSWORD` kullanıldığında parola process listesinden görülebileceği için güvenilmeyen ortamlarda etkileşimli giriş önerilir.

### İlk kullanım (kasa oluşturma)

```bash
fiotp init ~/.fiotp/kasa.json
# Master parola: ******** (en az 8 karakter)
```

Kasa dosyası `0600` izinleriyle oluşturulur.

### Hesap ekleme

Bir QR/URI'den (en yaygın yöntem — Google Authenticator, Bitwarden vb. hesapları aynı formattadır):

```bash
fiotp add ~/.fiotp/kasa.json "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
```

Google Authenticator'dan aktarma QR kodu (`otpauth-migration://` URI'si) ile toplu içe aktarma da desteklenir:

```bash
fiotp add ~/.fiotp/kasa.json "otpauth-migration://offline?data=Ci0K..."
```

Birden fazla hesap tek seferde içe aktarılır; tekrarlanan hesaplar otomatik atlanır. MD5 algoritmalı hesaplar desteklenmediği için atlanır ve uyarı verilir.

Ya da manuel olarak (issuer ve account sorulur):

```bash
fiotp add ~/.fiotp/kasa.json JBSWY3DPEHPK3PXP
```

HOTP hesapları da desteklenir (`otpauth://hotp/...&counter=0`).

### Hesapları listeleme

```bash
fiotp list ~/.fiotp/kasa.json
# 4de344c7-...  GitHub:user@example.com
# 8201146f-...  [hotp] Banka:alice
```

HOTP hesapları `[hotp]` etiketiyle işaretlenir.

### Kod üretme

Hesap seçicisi olarak hesap ID'si veya account adı verilir:

```bash
fiotp code ~/.fiotp/kasa.json user@example.com
# Kod: 123456  Kalan: 17 sn
```

- **TOTP** hesaplarında kod + kalan süre her saniye yenilenir (Ctrl+C ile çıkılır).
- **HOTP** hesaplarında kod tek seferlik basılır.

### QR gösterme

Hesabın otpauth URI'sini terminalde QR olarak çizer (başka bir cihaza aktarmak için):

```bash
fiotp qr ~/.fiotp/kasa.json user@example.com
```

### Yedekleme

Tüm kasa, şifreli JSON olarak dışa aktarılır (düz metin asla dışarı çıkmaz):

```bash
fiotp export ~/.fiotp/kasa.json ~/yedek.json
```

Yedeği aynı veya farklı bir kasaya geri yükler (tekrarlanan hesaplar atlanır):

```bash
fiotp import ~/.fiotp/kasa.json ~/yedek.json
```

### Master parola değiştirme

```bash
fiotp passwd ~/.fiotp/kasa.json
```

Mevcut parola yeniden doğrulanır; yeni parola iki kez istenir. Kasa tamamen yeni anahtarla yeniden şifrelenir.

### Canlı panel

Tüm TOTP hesaplarını tek ekranda, her saniye yenilenen kod ve kalan süreleriyle gösterir (Ctrl+C ile çıkılır):

```bash
fiotp watch ~/.fiotp/kasa.json
```

### Kasa kurtarma

`save()` her yazmadan önce mevcut dosyayı `<kasa>.bak` olarak yedekler. Kasa dosyanız bozulursa son iyi sürümü geri yükleyebilirsiniz:

```bash
fiotp recover ~/.fiotp/kasa.json
```

## Programatik API

fiotp aynı zamanda bir kütüphane olarak da kullanılabilir.

```ts
import { FiotpService } from "fiotp";

// Kasa aç
const service = await FiotpService.open("/tmp/kasa.json", "master-parola");

// URI'den hesap ekle
const account = service.addAccount(
  "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
);

// Kod üret (TOTP: kalan süreyle; HOTP: tek seferlik)
const code = service.getCode(account.id);
console.log(code.code, code.type === "totp" ? `${code.remainingSeconds} sn` : "");

// Kod doğrula (HOTP'ta sayaç otomatik ilerler)
const ok = await service.verifyCode(account.id, code.code);

// Canlı akış: her saniye yeni kod + kalan süre
const unsubscribe = service.subscribe(account.id, (tick) => {
  console.log(tick.code, tick.remainingSeconds);
});
unsubscribe();

// Şifreli yedek
const backup = await service.exportBackup();
const added = await service.importBackup(backup, "master-parola", "merge");

// Google Authenticator aktarma (otpauth-migration://)
const migrationResult = service.importMigration("otpauth-migration://offline?data=...");
console.log(`${migrationResult.added} hesap eklendi`);
console.log(`${migrationResult.skippedMd5} MD5 hesap atlandı`);

// Parola değiştir + kilit
await service.changeMasterPassword("master-parola", "yeni-parola");
service.lock();
```

Düşük seviyeli modüller de ayrıca dışa aktarılır (`src/index.ts`):

```ts
import { generateTOTP, verifyTOTP, parseOtpAuthUri, encrypt, decrypt, deriveKey } from "fiotp";
```

## Güvenlik Modeli

| Konu | Yaklaşım |
|---|---|
| Gizli anahtar depolama | AES-256-GCM, her şifrelemede rastgele 12 bayt IV + 16 bayt auth tag |
| Anahtar türetme | PBKDF2-HMAC-SHA256, 600.000 iterasyon, 16 bayt rastgele tuz |
| Parola doğrulama | Verifier bloğunun GCM etiketi üzerinden; parola türevi saklanmaz |
| Düz metin | Yalnızca kasa açıkken bellekte; `lock()` anahtarı sıfırlar |
| Otomatik kilit | 5 dk hareketsizlik (servis/CLI üzerinden ayarlanabilir, `null` ile kapatılır) |
| Dosya izinleri | Kasa ve yedekler `0600`, kasa dizinleri `0700` |
| Atomik yazma | Önce `.tmp`, sonra rename — yarıda kalan yazma dosyayı bozamaz |
| Doğrulama | TOTP/HOTP kodları sabit zamanlı (timing-safe) karşılaştırılır |
| Rate limiting | 5 ardışık başarısız denemeden sonra üstel geri çekilme (30 sn → 15 dk) |
| Yedekleme | Kasa zaten şifreli olduğundan export doğrudan şifreli JSON'dur; import kendi parolasıyla açılır |

## Proje Yapısı

```
src/
├── core/          # Modül 1 — crypto & çekirdek motor
│   ├── otp.ts     #   HOTP (RFC 4226) + TOTP (RFC 6238)
│   ├── base32.ts  #   RFC 4648 base32 + doğrulama
│   ├── cipher.ts  #   AES-256-GCM şifrele/çöz
│   ├── kdf.ts     #   PBKDF2-SHA256 anahtar türetme
│   └── errors.ts  #   FiotpError hiyerarşisi
├── storage/       # Modül 2 — şifreli yerel kasa
│   ├── vault.ts   #   VaultManager (aç/oluştur/kaydet/kilitle/parola değiştir)
│   ├── account.ts #   Hesap modeli + doğrulama
│   └── serialization.ts
├── parser/        # Modül 3 — otpauth:// URI ayrıştırma/üretme + migration
│   ├── otpauth.ts     # otpauth:// URI ayrıştırma/üretme
│   ├── migration.ts   # otpauth-migration:// Google Authenticator aktarma
│   └── protobuf.ts    # Minimal protobuf wire-format okuyucu (sıfır bağımlılık)
├── qr/            # Modül 3 — QR üretme (SVG/terminal/PNG) ve okuma (PNG)
├── service/       # Modül 4 — programatik servis facade + canlı akış
│   ├── fiotp.ts   #   FiotpService
│   └── ticker.ts  #   LiveCodeTicker (saniyelik yayın)
└── cli/           # Modül 4 — komut satırı arayüzü
tests/             # Vitest testleri (RFC vektörleri dahil)
```

## Geliştirme

```bash
npm run typecheck   # tip kontrolü (tsc --noEmit)
npm test            # tüm testler
npm run coverage    # test kapsam raporu
npm run build       # dist/ üret
```

Test paketi RFC 4226 Appendix D ve RFC 6238 Appendix B resmî test vektörlerini içerir; kasa yaşam döngüsü, kurcalama/bütünlük senaryoları, izinler, HOTP sayaç ilerleme, yedekleme ve parola değişimi kapsanır.

## Sınırlamalar

- QR okuma yalnızca **PNG** biçimindeki görüntüleri destekler (JPEG/WebP desteği yok).
- Web/kamera tabanlı QR tarama ve grafiksel kullanıcı arayüzü henüz yok.
- Rate limiting durumu yalnızca bellekte tutulur; süreç yeniden başladığında sayaç sıfırlanır.
