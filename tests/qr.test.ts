import { describe, expect, it } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { QrDecodeError } from "../src/core/errors.js";
import { decodeQrFromPng, decodeQrFromPngFile } from "../src/qr/decode.js";
import { renderQrPng, renderQrSvg, renderQrTerminal } from "../src/qr/encode.js";

const URI = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example";

describe("QR encode/decode", () => {
  it("SVG üretmeli", async () => {
    const svg = await renderQrSvg(URI);
    expect(svg).toContain("<svg");
    expect(svg).toContain("viewBox");
  });

  it("terminal çıktısı üretmeli", async () => {
    const terminal = await renderQrTerminal(URI);
    expect(terminal.length).toBeGreaterThan(0);
  });

  it("PNG üretip tekrar okuyabilmeli", async () => {
    const png = await renderQrPng(URI, { width: 300 });
    expect(png[0]).toBe(0x89);
    expect(decodeQrFromPng(png)).toBe(URI);
  });

  it("boş PNG'de QrDecodeError fırlatmalı", () => {
    expect(() => decodeQrFromPng(new Uint8Array())).toThrow(QrDecodeError);
  });

  it("bozuk görüntüde QrDecodeError fırlatmalı", () => {
    expect(() => decodeQrFromPng(new Uint8Array([1, 2, 3, 4]))).toThrow(
      QrDecodeError,
    );
  });

  it("PNG dosyasından QR okuyabilmeli", async () => {
    const directory = await mkdtemp(join(tmpdir(), "fiotp-qr-"));
    const path = join(directory, "kod.png");
    try {
      await writeFile(path, await renderQrPng(URI));
      expect(await decodeQrFromPngFile(path)).toBe(URI);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("olmayan dosyada QrDecodeError fırlatmalı", async () => {
    await expect(
      decodeQrFromPngFile(join(tmpdir(), "olmayan-dosya.png")),
    ).rejects.toThrow(QrDecodeError);
  });
});
