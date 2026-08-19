import { readFile } from "node:fs/promises";
import jsQR from "jsqr";
import { PNG } from "pngjs";
import { QrDecodeError } from "../core/errors.js";

/** PNG bayt dizisindeki ilk QR kodunu çözer. */
export function decodeQrFromPng(pngBytes: Uint8Array): string {
  if (pngBytes.length === 0) {
    throw new QrDecodeError("PNG verisi boş");
  }

  try {
    const image = PNG.sync.read(Buffer.from(pngBytes));
    const decode = jsQR as unknown as (
      data: Uint8ClampedArray,
      width: number,
      height: number,
    ) => { data: string } | null;
    const result = decode(
      new Uint8ClampedArray(image.data),
      image.width,
      image.height,
    );
    if (result === null || result.data.length === 0) {
      throw new QrDecodeError("görüntüde QR kod bulunamadı");
    }
    return result.data;
  } catch (error) {
    if (error instanceof QrDecodeError) throw error;
    throw new QrDecodeError("PNG okunamadı veya görüntü bozuk");
  }
}

/** PNG dosyasını okuyup içindeki QR kodunu çözer. */
export async function decodeQrFromPngFile(path: string): Promise<string> {
  try {
    return decodeQrFromPng(new Uint8Array(await readFile(path)));
  } catch (error) {
    if (error instanceof QrDecodeError) throw error;
    throw new QrDecodeError("PNG dosyası okunamadı");
  }
}
