import { ECB } from './ecb';
import { CBC } from './cbc';

/**
 * Decrypts a given buffer of data using tc_tea (CBC).
 * @param buffer - encrypted data.
 * @param key - key buffer
 * @throws {TcTeaPaddingError} Padding validation failed, either invalid cipher text or invalid key.
 * @throws {TcTeaSizeError} Input should be multiple of 8 and at least 10 bytes.
 * @returns Decrypted data
 */
export function decrypt(buffer: Uint8Array, key: string | Uint8Array): Uint8Array {
  return CBC.fromKey(key).decrypt(buffer);
}

/**
 * Encrypts a given buffer of data using tc_tea (CBC).
 * @param buffer - encrypted data.
 * @param key - key buffer
 * @throws {TcTeaPaddingError} Padding validation failed, either invalid cipher text or invalid key.
 * @throws {TcTeaSizeError} Input should be multiple of 8 and at least 10 bytes.
 * @returns Encrypted data
 */
export function encrypt(buffer: Uint8Array, key: string | Uint8Array): Uint8Array {
  return CBC.fromKey(key).encrypt(buffer);
}

export { encrypt as oi_symmetry_encrypt2, decrypt as oi_symmetry_decrypt2 };

/**
 * Encrypts a single block using tc_tea_ecb (insecure).
 * @param buffer - plain text. Encrypted data will be written back to this buffer.
 * @param key - key buffer
 */
export function TeaEncryptECB(buffer: Uint8Array, key: string | Uint8Array) {
  return new ECB(key).encrypt(buffer);
}

/**
 * Decrypts a single block using tc_tea_ecb (insecure).
 * @param buffer - plain text. Decrypted data will be written back to this buffer.
 * @param key - key buffer
 */
export function TeaDecryptECB(buffer: Uint8Array, key: string | Uint8Array) {
  return new ECB(key).decrypt(buffer);
}

export { ECB, CBC };
