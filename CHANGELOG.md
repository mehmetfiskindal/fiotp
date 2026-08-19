# Değişiklik Günlüğü

Bu proje [Semantic Versioning](https://semver.org/lang/tr/) ve [Keep a Changelog](https://keepachangelog.com/tr/1.1.0/) formatını takip eder.

## [0.1.0] - 2026-08-19

### Eklendi

- RFC 4226 (HOTP) ve RFC 6238 (TOTP) uyumlu kod üretimi (SHA-1/256/512, 6-10 hane, özel periyot)
- AES-256-GCM ile şifrelenmiş yerel kasa; PBKDF2-HMAC-SHA256 (600.000 iterasyon) anahtar türetme
- `otpauth://` URI ayrıştırma/üretme ve Google Authenticator toplu aktarım desteği (`otpauth-migration://`)
- QR kod üretme (SVG/terminal/PNG) ve PNG QR okuma (saf JS, native bağımlılık yok)
- Canlı kod akışı (`watch`, `subscribe`) ve HOTP resync penceresi
- Şifreli JSON export/import (merge/replace), master parola değiştirme, otomatik kasa yedekleme (`.bak`) ve kurtarma
- CLI: `init`, `add`, `list`, `code`, `qr`, `export`, `import`, `passwd`, `watch`, `recover`
- Programatik API: `FiotpService` facade ve düşük seviyeli modüller (`generateTOTP`, `parseOtpAuthUri`, `encrypt`, `deriveKey`, vb.)
- Dosya izinleri (0600/0700), atomik yazma (tmp + rename), rate limiting (üstel geri çekilme) ve otomatik kilit

[0.1.0]: https://github.com/mehmetfiskindal/fiotp/releases/tag/v0.1.0
