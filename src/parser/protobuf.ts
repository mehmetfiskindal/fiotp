/**
 * Minimal protobuf wire-format okuyucu.
 *
 * Google Authenticator aktarım dosyasını (`MigrationPayload`) çözmek için
 * gerekli olan küçük bir alt küme uygulanır; tam bir protobuf kütüphanesi
 * gerekmez. Desteklenen wire type'lar: 0 (varint), 1 (fixed64), 2
 * (length-delimited), 5 (fixed32).
 */

/** Bir alanın (tag) çözümlenmiş hali. */
export interface ProtobufField {
  fieldNumber: number;
  wireType: number;
}

export class ProtobufReader {
  private offset = 0;

  public constructor(private readonly buffer: Uint8Array) {}

  public get eof(): boolean {
    return this.offset >= this.buffer.length;
  }

  /** Bir sonraki alanın tag'ini okur; tampon bittiyse `null` döner. */
  public readField(): ProtobufField | null {
    if (this.eof) {
      return null;
    }
    const tag = this.readVarint();
    return {
      fieldNumber: Number(tag >> 3n),
      wireType: Number(tag & 0x07n),
    };
  }

  /** Bir varint okur (bigint olarak; sayı değerleri büyük olabilir). */
  public readVarint(): bigint {
    let result = 0n;
    let shift = 0n;
    for (;;) {
      if (this.offset >= this.buffer.length) {
        throw new Error("kesik varint");
      }
      const byte = this.buffer[this.offset++]!;
      result |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) {
        break;
      }
      shift += 7n;
      if (shift > 63n) {
        throw new Error("varint taşması");
      }
    }
    return result;
  }

  /** `wireType: 2` alanının uzunluk önekini okuyup baytlarını döndürür. */
  public readLengthDelimited(): Uint8Array {
    const length = Number(this.readVarint());
    if (length < 0 || this.offset + length > this.buffer.length) {
      throw new Error("kesik length-delimited alan");
    }
    const slice = this.buffer.subarray(this.offset, this.offset + length);
    this.offset += length;
    return slice;
  }

  /** Bilinmeyen bir alanı wire type'ına göre atlar. */
  public skipField(wireType: number): void {
    switch (wireType) {
      case 0:
        this.readVarint();
        break;
      case 1:
        this.offset += 8;
        break;
      case 2:
        this.readLengthDelimited();
        break;
      case 5:
        this.offset += 4;
        break;
      default:
        throw new Error(`desteklenmeyen wire type: ${wireType}`);
    }
  }

  /** Baytları UTF-8 metne çevirir. */
  public static decodeUtf8(bytes: Uint8Array): string {
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  }
}
