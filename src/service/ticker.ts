import type { OtpAccount } from "../storage/account.js";
import { generateTOTP, type TotpCode } from "../core/otp.js";

/** Saniyelik canlı kod yayını. */
export interface OtpTick extends TotpCode {
  accountId: string;
}

export type OtpTickListener = (tick: OtpTick) => void;

/**
 * Abone olunan TOTP hesapları için tek bir saniyelik timer yönetir.
 * Son abone ayrıldığında timer otomatik olarak durur.
 */
export class LiveCodeTicker {
  private readonly listeners = new Map<string, Set<OtpTickListener>>();
  private timer: ReturnType<typeof setInterval> | null = null;

  public constructor(private readonly getAccount: (id: string) => OtpAccount) {}

  /** Bir hesaba abone olur ve hemen ilk tick'i gönderir. */
  public subscribe(accountId: string, listener: OtpTickListener): () => void {
    const account = this.getAccount(accountId);
    const accountListeners = this.listeners.get(accountId) ?? new Set();
    accountListeners.add(listener);
    this.listeners.set(accountId, accountListeners);
    this.emit(account, listener);
    this.start();

    return () => {
      const current = this.listeners.get(accountId);
      current?.delete(listener);
      if (current?.size === 0) this.listeners.delete(accountId);
      if (this.listeners.size === 0) this.stop();
    };
  }

  /** Tüm abonelikleri ve timer'ı durdurur. */
  public stop(): void {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.listeners.clear();
  }

  /** Aktif hesap aboneliği var mı? */
  public get isRunning(): boolean {
    return this.timer !== null;
  }

  private start(): void {
    if (this.timer !== null) return;
    this.timer = setInterval(() => this.tick(), 1_000);
    this.timer.unref?.();
  }

  private tick(): void {
    for (const [accountId, accountListeners] of this.listeners) {
      try {
        const account = this.getAccount(accountId);
        for (const listener of accountListeners) this.emit(account, listener);
      } catch {
        // Hesap silinmiş veya kasa kilitlenmişse abonelik artık geçersizdir.
        this.listeners.delete(accountId);
      }
    }
    if (this.listeners.size === 0) this.stop();
  }

  private emit(account: OtpAccount, listener: OtpTickListener): void {
    const code = generateTOTP(account.secret, undefined, {
      algorithm: account.algorithm,
      digits: account.digits,
      period: account.period,
    });
    listener({ accountId: account.id, ...code });
  }
}
