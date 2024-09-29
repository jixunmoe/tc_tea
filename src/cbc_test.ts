import { test } from 'node:test';
import { CBC } from './cbc';
import * as assert from 'node:assert';

test('cbc:decrypt', () => {
  const tea = CBC.fromKey('12345678ABCDEFGH');
  const data = new Uint8Array([
    0x91, 0x09, 0x51, 0x62, 0xe3, 0xf5, 0xb6, 0xdc, 0x6b, 0x41, 0x4b, 0x50, 0xd1, 0xa5, 0xb8, 0x4e, 0xc5, 0x0d, 0x0c,
    0x1b, 0x11, 0x96, 0xfd, 0x3c,
  ]);
  const expected = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  const decrypted = tea.decrypt(data);
  assert.deepEqual(decrypted, expected);
});

test('cbc:encrypt', () => {
  const tea = CBC.fromKey('12345678ABCDEFGH');
  const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 0xff, 0xfe]);
  const expected = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 0xff, 0xfe]);
  const encrypted = tea.encrypt(data);
  const decrypted = tea.decrypt(encrypted);
  assert.deepEqual(decrypted, expected);
});
