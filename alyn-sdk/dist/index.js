"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.query = exports.call = exports.deploy = void 0;
exports.encodeL2Tx = encodeL2Tx;
exports.decodeL2Tx = decodeL2Tx;
exports.encodeCalldata = encodeCalldata;
function encodeL2Tx(tx) {
    const json = JSON.stringify({
        to: tx.to,
        data: Buffer.from(tx.data).toString('hex'),
        value: tx.value !== undefined ? tx.value.toString() : undefined,
    });
    return Buffer.from(json);
}
function decodeL2Tx(bytes) {
    const obj = JSON.parse(Buffer.from(bytes).toString());
    return {
        to: obj.to,
        data: Uint8Array.from(Buffer.from(obj.data, 'hex')),
        value: obj.value !== undefined ? BigInt(obj.value) : undefined,
    };
}
async function rpc(url, method, params) {
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
const deploy = (url, tx) => rpc(url, 'l2_deploy', [Array.from(encodeL2Tx(tx))]);
exports.deploy = deploy;
const call = (url, tx) => rpc(url, 'l2_call', [Array.from(encodeL2Tx(tx))]);
exports.call = call;
const query = (url, tx) => rpc(url, 'l2_query', [Array.from(encodeL2Tx(tx))]);
exports.query = query;
function encodeCalldata(fn, bytes) {
    const nameBytes = Buffer.from(fn, 'utf8');
    const out = new Uint8Array(nameBytes.length + bytes.length);
    out.set(nameBytes, 0);
    out.set(bytes, nameBytes.length);
    return out;
}
