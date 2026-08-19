import { TooManyAttemptsError } from "../core/errors.js";

/** Başarısız parola denemelerini izleyen ve üstel geri çekilme uygulayan mekanizma. */
export interface LoginThrottleOptions {
  /** Kilitleme öncesi izin verilen ardışık başarısızlık sayısı. Varsayılan: 5. */
  maxAttempts?: number;
  /** İlk kilitleme süresi (ms). Varsayılan: 30 saniye. */
  baseBackoffMs?: number;
  /** Kilitleme süresinin üst sınırı (ms). Varsayılan: 15 dakika. */
  maxBackoffMs?: number;
  /** Zaman kaynağı (testlerde sahte saat kullanımı için). */
  now?: () => number;
}

interface AttemptState {
  count: number;
  lockedUntil: number;
  backoffMs: number;
}

/**
 * Kasa yollarına göre anahtarlanmış, bellek içi oturum sınırlayıcı.
 *
 * PBKDF2'nin getirdiği doğal maliyete ek olarak, ardışık başarısız denemeler
 * sonrası `TooManyAttemptsError` ile geçici kilit uygulanarak çevrimdışı
 * brute-force saldırıları yavaşlatılır. Durum yalnızca bellekte tutulur;
 * süreç yeniden başladığında sayaç sıfırlanır.
 */
export class LoginThrottle {
  private readonly states = new Map<string, AttemptState>();
  private readonly maxAttempts: number;
  private readonly baseBackoffMs: number;
  private readonly maxBackoffMs: number;
  private readonly now: () => number;

  public constructor(options: LoginThrottleOptions = {}) {
    this.maxAttempts = options.maxAttempts ?? 5;
    this.baseBackoffMs = options.baseBackoffMs ?? 30_000;
    this.maxBackoffMs = options.maxBackoffMs ?? 900_000;
    this.now = options.now ?? Date.now;
  }

  /**
   * Verilen yol için deneme yapılabilir mi kontrol eder.
   *
   * @throws {TooManyAttemptsError} Yol geçici olarak kilitliyse.
   */
  public check(path: string): void {
    const state = this.states.get(path);
    if (state === undefined) {
      return;
    }
    const remaining = state.lockedUntil - this.now();
    if (remaining > 0) {
      throw new TooManyAttemptsError(remaining);
    }
    // Kilit süresi doldu: kilit kalkar ama backoff bilgisi (eskalasyon) korunur.
    state.lockedUntil = 0;
  }

  /** Başarısız bir denemeyi kaydeder; eşiğe ulaşıldıysa kilit uygular. */
  public recordFailure(path: string): void {
    const current = this.states.get(path);
    const state: AttemptState = current ?? {
      count: 0,
      lockedUntil: 0,
      backoffMs: this.baseBackoffMs,
    };
    state.count += 1;
    if (state.count >= this.maxAttempts) {
      state.lockedUntil = this.now() + state.backoffMs;
      state.backoffMs = Math.min(state.backoffMs * 2, this.maxBackoffMs);
      state.count = 0;
    }
    this.states.set(path, state);
  }

  /** Başarılı bir denemeyi kaydeder ve tüm sayacı sıfırlar. */
  public recordSuccess(path: string): void {
    this.states.delete(path);
  }
}
