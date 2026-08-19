import QRCode from "qrcode";
import { InvalidParameterError } from "../core/errors.js";

/** QR SVG üretim seçenekleri. */
export interface QrSvgOptions {
  width?: number;
  margin?: number;
  errorCorrectionLevel?: "L" | "M" | "Q" | "H";
}

/** QR kodunu SVG metni olarak üretir. */
export async function renderQrSvg(
  text: string,
  options: QrSvgOptions = {},
): Promise<string> {
  if (text.length === 0) throw new InvalidParameterError("text", "boş olamaz");
  return QRCode.toString(text, {
    type: "svg",
    width: options.width,
    margin: options.margin ?? 2,
    errorCorrectionLevel: options.errorCorrectionLevel ?? "M",
  });
}

/** QR kodunu terminalde gösterilebilen UTF-8 blok metni olarak üretir. */
export async function renderQrTerminal(text: string): Promise<string> {
  if (text.length === 0) throw new InvalidParameterError("text", "boş olamaz");
  return QRCode.toString(text, {
    type: "terminal",
    small: true,
    errorCorrectionLevel: "M",
  });
}

/** QR kodunu PNG bayt dizisi olarak üretir. */
export async function renderQrPng(
  text: string,
  options: QrSvgOptions = {},
): Promise<Uint8Array> {
  if (text.length === 0) throw new InvalidParameterError("text", "boş olamaz");
  const buffer = await QRCode.toBuffer(text, {
    type: "png",
    width: options.width ?? 256,
    margin: options.margin ?? 2,
    errorCorrectionLevel: options.errorCorrectionLevel ?? "M",
  });
  return new Uint8Array(buffer);
}
