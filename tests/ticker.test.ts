import { beforeEach, describe, expect, it, vi } from "vitest";
import { LiveCodeTicker, type OtpTick } from "../src/service/ticker.js";
import type { OtpAccount } from "../src/storage/account.js";

const account: OtpAccount = {
  id: "account-1",
  issuer: "Example",
  account: "alice",
  secret: "JBSWY3DPEHPK3PXP",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  createdAt: 1,
};

describe("LiveCodeTicker", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(1_700_000_000_000));
  });

  it("hemen ve her saniye tick göndermeli", () => {
    const ticks: OtpTick[] = [];
    const ticker = new LiveCodeTicker((id) => {
      if (id !== account.id) throw new Error("not found");
      return account;
    });
    const unsubscribe = ticker.subscribe(account.id, (tick) => ticks.push(tick));

    expect(ticks).toHaveLength(1);
    expect(ticks[0]!.remainingSeconds).toBe(10);
    vi.advanceTimersByTime(1_000);
    expect(ticks).toHaveLength(2);
    expect(ticks[1]!.remainingSeconds).toBe(9);
    unsubscribe();
    expect(ticker.isRunning).toBe(false);
    vi.useRealTimers();
  });

  it("birden fazla dinleyiciyi desteklemeli ve stop temizlemeli", () => {
    const first: OtpTick[] = [];
    const second: OtpTick[] = [];
    const ticker = new LiveCodeTicker(() => account);
    const unsubscribe = ticker.subscribe(account.id, (tick) => first.push(tick));
    ticker.subscribe(account.id, (tick) => second.push(tick));
    vi.advanceTimersByTime(1_000);
    expect(first).toHaveLength(2);
    expect(second).toHaveLength(2);
    unsubscribe();
    expect(ticker.isRunning).toBe(true);
    ticker.stop();
    expect(ticker.isRunning).toBe(false);
    vi.useRealTimers();
  });
});
