import { ECB } from './ecb';

const kSaltLen = 2;
const kZeroLen = 7;
const kFixedPaddingLen = 1 + kSaltLen + kZeroLen;

function xorBlock(dst: Uint8Array, key1: Uint8Array, key2: Uint8Array) {
  for (let i = 0; i < 8; i++) {
    dst[i] = key1[i] ^ key2[i];
  }
}

/**
 * TC_TEA_CBC: Tencent modified TEA using CBC block mode.
 */
export class CBC {
  constructor(private ecb: ECB) {}

  static fromKey(key: Uint8Array | string): CBC {
    return new CBC(new ECB(key));
  }

  /**
   * Encrypts a given buffer of data using tc_tea (CBC).
   *
   * @param {Uint8Array} buf - The input buffer to be encrypted.
   * @return {Uint8Array} - The encrypted output buffer.
   */
  encrypt(buf: Uint8Array): Uint8Array {
    const length = buf.byteLength + kFixedPaddingLen;
    const paddingLength = (8 - (length % 8)) % 8;
    const outputLength = length + paddingLength;

    const result = new Uint8Array(outputLength);
    const headerLength = 1 + paddingLength + kSaltLen;
    for (let i = 0; i < headerLength; i++) {
      result[i] = Math.random() * 256;
    }
    result[0] = (result[0] << 3) | (paddingLength & 7);
    result.subarray(headerLength).set(buf);

    const iv1 = new Uint8Array(8);
    const iv2 = new Uint8Array(8);
    const iv2Next = new Uint8Array(8);
    for (let i = 0; i < outputLength; i += 8) {
      const block = result.subarray(i, i + 8);
      xorBlock(block, block, iv1);
      iv2Next.set(block);
      this.ecb.encrypt(block);

      // update block/iv1/iv2
      xorBlock(block, block, iv2);
      iv1.set(block);
      iv2.set(iv2Next);
    }
    return result;
  }

  /**
   * Decrypts a given buffer of data using tc_tea (CBC).
   * @param buf Encrypted data.
   * @throws {TcTeaPaddingError} Padding validation failed, either invalid cipher text or invalid key.
   * @throws {TcTeaSizeError} Input should be multiple of 8 and at least 10 bytes.
   * @returns Decrypted data
   */
  decrypt(buf: Uint8Array): Uint8Array {
    const bufferLength = buf.byteLength;
    if (bufferLength < 10 || bufferLength % 8 != 0) {
      throw new TcTeaSizeError();
    }

    const result = new Uint8Array(buf);

    const iv1 = new Uint8Array(8);
    const iv2 = new Uint8Array(8);
    const nextIv1 = new Uint8Array(8);
    for (let i = 0; i < bufferLength; i += 8) {
      const block = result.subarray(i, i + 8);
      nextIv1.set(block);
      xorBlock(block, block, iv2);
      this.ecb.decrypt(block);

      // update block/iv1/iv2
      iv2.set(block);
      xorBlock(block, block, iv1);
      iv1.set(nextIv1);
    }

    const padSize = result[0] & 7;
    const startLoc = 1 + padSize + 2;
    const endLoc = bufferLength - 7;

    let checkValue = 0;
    for (let i = endLoc; i < bufferLength; i++) {
      checkValue |= result[i];
    }
    if (checkValue != 0) {
      throw new TcTeaPaddingError();
    }
    return result.subarray(startLoc, endLoc);
  }
}

export class TcTeaPaddingError extends Error {
  constructor() {
    super('Invalid plain text padding');
  }
}

export class TcTeaSizeError extends Error {
  constructor() {
    super('Invalid buffer size (need to be block of 8, min 10 bytes)');
  }
}
