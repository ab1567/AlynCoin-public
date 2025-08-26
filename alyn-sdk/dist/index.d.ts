export interface L2Tx {
    to: string;
    data: Uint8Array;
    value?: bigint;
}
export declare function encodeL2Tx(tx: L2Tx): Uint8Array;
export declare function decodeL2Tx(bytes: Uint8Array): L2Tx;
export declare const deploy: (url: string, tx: L2Tx) => Promise<any>;
export declare const call: (url: string, tx: L2Tx) => Promise<any>;
export declare const query: (url: string, tx: L2Tx) => Promise<any>;
export declare function encodeCalldata(fn: string, bytes: Uint8Array): Uint8Array;
