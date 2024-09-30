const TEA_ROUNDS = 16;
const TEA_DELTA = 0x9e3779b9;
const TEA_SUM = TEA_DELTA * TEA_ROUNDS;

function ecb_single_round(value: number, sum: number, key1: number, key2: number) {
  const left = (value << 4) + key1;
  const right = (value >>> 5) + key2;
  const mid = sum + value;

  return left ^ mid ^ right;
}

/**
 * TC_TEA_ECB: Tencent modified TEA using ECB block mode (insecure).
 */
export class ECB {
  keys: Int32Array;

  /**
   * Constructs tc_tea ECB cipher.
   *
   * @param key - The key to be used for initialization.
   */
  constructor(key: Uint8Array | string) {
    if (typeof key === 'string') {
      key = Uint8Array.from(Array.from(key, (x) => x.charCodeAt(0)));
    }

    const view = new DataView(key.buffer, key.byteOffset, key.byteLength);
    this.keys = Int32Array.from([0, 0, 0, 0].map((_, idx) => view.getUint32(idx * 4, false)));
  }

  /**
   * Decrypts a block of data using TC's TEA, in ECB mode.
   *
   * @param buffer - The input buffer containing encrypted data. Decrypted data will be written back.
   */
  decrypt(buffer: Uint8Array) {
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    let y = view.getInt32(0, false);
    let z = view.getInt32(4, false);

    const { keys } = this;
    for (let i = 0, sum = TEA_SUM; i < TEA_ROUNDS; i++) {
      z -= ecb_single_round(y, sum, keys[2], keys[3]);
      y -= ecb_single_round(z, sum, keys[0], keys[1]);
      sum -= TEA_DELTA;
    }

    view.setInt32(0, y, false);
    view.setInt32(4, z, false);
  }

  /**
   * Encrypts a block of data using TC's TEA, in ECB mode.
   *
   * @param buffer - The input buffer containing encrypted data. Encrypted data will be written back.
   */
  encrypt(buffer: Uint8Array) {
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

    let y = view.getInt32(0, false);
    let z = view.getInt32(4, false);

    const { keys } = this;
    for (let i = 0, sum = 0; i < TEA_ROUNDS; i++) {
      sum += TEA_DELTA;
      y += ecb_single_round(z, sum, keys[0], keys[1]);
      z += ecb_single_round(y, sum, keys[2], keys[3]);
    }

    view.setInt32(0, y, false);
    view.setInt32(4, z, false);
  }
}
