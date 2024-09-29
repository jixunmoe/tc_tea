import { test } from 'node:test';
import { ECB } from './ecb';
import * as assert from 'node:assert';

test('ecb:decrypt', () => {
  const tea = new ECB('\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x00');
  const data = new Uint8Array([0x56, 0x27, 0x6b, 0xa9, 0x80, 0xb9, 0xec, 0x16]);
  const expected = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  tea.decrypt(data);
  assert.deepEqual(data, expected);
});

test('ecb:encrypt', () => {
  const tea = new ECB('\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x00');
  const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  const expected = new Uint8Array([0x56, 0x27, 0x6b, 0xa9, 0x80, 0xb9, 0xec, 0x16]);
  tea.encrypt(data);
  assert.deepEqual(data, expected);
});

test('ecb:encrypt - negative input', () => {
  const tea = new ECB('\x7f\xff\xff\xf1\x7f\xff\xff\xf2\x7f\xff\xff\xf3\x7f\xff\xff\xf4');
  const data = new Uint8Array([0x7f, 1, 2, 3, 0x80, 4, 5, 6]);
  const expected = new Uint8Array([0x59, 0x6a, 0x9d, 0x4c, 0x5c, 0xf8, 0x66, 0x24]);
  tea.encrypt(data);
  assert.deepEqual(data, expected);
});
