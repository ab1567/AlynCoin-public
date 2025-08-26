import { encodeL2Tx, decodeL2Tx, encodeCalldata } from '../src';

describe('L2Tx encoding', () => {
  test('round trip', () => {
    const tx = { to: '0xabc', data: Uint8Array.from([1,2,3]), value: 5n };
    const encoded = encodeL2Tx(tx);
    const decoded = decodeL2Tx(encoded);
    expect(decoded.to).toBe(tx.to);
    expect(Array.from(decoded.data)).toEqual([1,2,3]);
    expect(decoded.value).toBe(5n);
  });
});

describe('calldata builder', () => {
  test('concatenates name and bytes', () => {
    const out = encodeCalldata('foo', Uint8Array.from([1,2]));
    expect(Array.from(out)).toEqual([...Buffer.from('foo'),1,2]);
  });
});
