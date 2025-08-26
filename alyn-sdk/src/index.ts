export interface L2Tx {
  to: string;
  data: Uint8Array;
  value?: bigint;
}

export function encodeL2Tx(tx: L2Tx): Uint8Array {
  const json = JSON.stringify({
    to: tx.to,
    data: Buffer.from(tx.data).toString('hex'),
    value: tx.value !== undefined ? tx.value.toString() : undefined,
  });
  return Buffer.from(json);
}

export function decodeL2Tx(bytes: Uint8Array): L2Tx {
  const obj = JSON.parse(Buffer.from(bytes).toString());
  return {
    to: obj.to,
    data: Uint8Array.from(Buffer.from(obj.data, 'hex')),
    value: obj.value !== undefined ? BigInt(obj.value) : undefined,
  };
}

async function rpc(url: string, method: string, params: unknown[]): Promise<any> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const json = await res.json();
  if (json.error) {
    throw new Error(json.error.message);
  }
  return json.result;
}

export const deploy = (url: string, tx: L2Tx) => rpc(url, 'l2_deploy', [Array.from(encodeL2Tx(tx))]);
export const call = (url: string, tx: L2Tx) => rpc(url, 'l2_call', [Array.from(encodeL2Tx(tx))]);
export const query = (url: string, tx: L2Tx) => rpc(url, 'l2_query', [Array.from(encodeL2Tx(tx))]);

export function encodeCalldata(fn: string, bytes: Uint8Array): Uint8Array {
  const nameBytes = Buffer.from(fn, 'utf8');
  const out = new Uint8Array(nameBytes.length + bytes.length);
  out.set(nameBytes, 0);
  out.set(bytes, nameBytes.length);
  return out;
}
