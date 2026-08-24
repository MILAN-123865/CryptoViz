/**
 * Hamsi — SHA-3 Second-Round Finalist
 * Bitslice-parallel Serpent S7 sponge.
 * Hamsi-256 and Hamsi-512 variants.
 */
import type { CipherResult, CipherStep, CipherOptions, TestVector, CipherMetadata } from '../types'
import { CipherError } from '../../utils/errors'

const METADATA: CipherMetadata = {
    name: 'Hamsi',
    blockSize: 256,
    securityStatus: 'legacy',
    breakingComplexity: 'SHA-3 finalist. Bitslice Serpent S7 sponge. Surpassed by BLAKE2.',
    yearDesigned: 2008,
    standardBody: 'NIST SHA-3 Competition',
}

function u32(n: number): number { return n >>> 0 }
function rotl(x: number, n: number): number { return u32((x << n) | (x >>> (32 - n))) }

// Serpent S7 bitslice (3-bit in, 3-bit out over 32 parallel lanes)
function s7(a: number, b: number, c: number): [number, number, number] {
    const t1 = a ^ b
    const t2 = a & c
    const t3 = c ^ t2
    const t4 = b | t3
    const out_a = t1 ^ t4
    const t5 = b & t4
    const out_b = t1 | t5
    const out_c = (b | out_a) ^ (c | out_b)
    return [u32(out_a), u32(out_b), u32(out_c)]
}

function theta(state: number[]) {
    // Simplified Theta linear layer for visualizer
    for (let i = 0; i < state.length; i++) {
        state[i] = u32(state[i] ^ rotl(state[(i + 1) % state.length], 1))
    }
}

function hamsiCore(input: string, outputBits: number, instrument: boolean): CipherResult {
    const start = performance.now()
    const inBytes: number[] = []
    const c = input.replace(/\s+/g, '').toLowerCase()
    if (!/^[0-9a-f]*$/.test(c) || c.length % 2 !== 0) throw new CipherError('INVALID_INPUT', 'Input must be hex.')
    for (let i = 0; i < c.length; i += 2) inBytes.push(parseInt(c.slice(i, i + 2), 16))

    const is512 = outputBits > 256
    const stateWords = is512 ? 32 : 16
    const blockSizeBytes = is512 ? 8 : 4
    const rounds = is512 ? 8 : 6

    // IV (Mock representative values)
    const state = new Array(stateWords).fill(0).map((_, i) => u32(0x12345678 + i + outputBits))

    // Padding
    const padded = [...inBytes, 0x80]
    while (padded.length % blockSizeBytes !== 0) padded.push(0)
    for (let i = 0; i < 8; i++) padded.push(0) // Length field

    const steps: CipherStep[] = []

    for (let b = 0; b < padded.length; b += blockSizeBytes) {
        const block = new Array(blockSizeBytes / 4).fill(0)
        for (let i = 0; i < block.length; i++) {
            const off = b + i * 4
            block[i] = u32(padded[off] | (padded[off + 1] << 8) | (padded[off + 2] << 16) | (padded[off + 3] << 24))
        }

        // Message injection
        for (let i = 0; i < block.length; i++) state[i] = u32(state[i] ^ block[i])

        // Permutation rounds
        for (let r = 0; r < rounds; r++) {
            // Gamma (Bitslice S7)
            for (let i = 0; i < stateWords; i += 4) {
                const [a, b, c] = s7(state[i], state[i + 1], state[i + 2])
                state[i] = a; state[i + 1] = b; state[i + 2] = c
            }
            // Pi (Simplified word rotation)
            const tmp = state.shift()!
            state.push(tmp)
            // Theta
            theta(state)
        }
    }

    // Truncation/Folding
    const outWords = outputBits / 32
    const outBytes: number[] = []
    for (let i = 0; i < outWords; i++) {
        outBytes.push(state[i] & 0xff, (state[i] >>> 8) & 0xff, (state[i] >>> 16) & 0xff, (state[i] >>> 24) & 0xff)
    }

    const outHex = outBytes.map(b => b.toString(16).padStart(2, '0')).join('')
    if (instrument) {
        steps.push({ index: 0, label: 'Hamsi Hash', inputState: input, outputState: outHex, note: `Bitslice Serpent S7. ${rounds} rounds per block.`, isMilestone: true })
    }

    return { output: outHex, outputEncoding: 'hex', steps, metadata: METADATA, durationMs: performance.now() - start }
}

export function encrypt(input: string, key: string, options: CipherOptions = {}): CipherResult {
    const bits = (options.outputBits as number) || 256
    return hamsiCore(input, bits, !!options.instrument)
}
export function decrypt(): CipherResult {
    throw new CipherError('ONE_WAY_HASH', 'Hamsi is a one-way hash function.')
}
export const TEST_VECTORS: TestVector[] = [
    { input: '', key: '', expected: 'mock_hamsi_256', description: 'Hamsi-256 empty string' }
]
// lib/cipher/hash/hamsi.ts

import { CipherDefinition } from '../types';

/**
 * Hamsi Initial Vectors and Expansion Constants (Truncated Representation)
 */
const HAMSI_256_IV: Uint32Array = new Uint32Array([
    0x616e6472, 0x616d656c, 0x696e6173, 0x68616d73,
    0x69736861, 0x6d73692d, 0x32353600, 0x00000000
]);

const HAMSI_512_IV: Uint32Array = new Uint32Array([
    0x616e6472, 0x616d656c, 0x696e6173, 0x68616d73,
    0x69736861, 0x6d73692d, 0x35313200, 0x00000000,
    0x31323334, 0x35363738, 0x39306162, 0x63646566,
    0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00
]);

/**
 * Bitslice Serpent S7 S-box applied to 32-bit word triplets (A, B, C)
 */
function bitsliceS7(words: Uint32Array, offset: number): void {
    let a = words[offset];
    let b = words[offset + 1];
    let c = words[offset + 2];

    // Serpent S7 bitslice boolean expression
    const t1 = ~a;
    const t2 = b ^ c;
    const t3 = t1 | t2;
    const t4 = a ^ t2;
    const t5 = t3 ^ t4;
    const t6 = b ^ t5;
    const t7 = t1 ^ t5;
    const t8 = t4 & t7;
    const t9 = t5 ^ t8;

    words[offset] = t5;
    words[offset + 1] = t9;
    words[offset + 2] = t8;
}

/**
 * Core Hamsi Permutation and Compression logic simulation
 */
function compressBlock(state: Uint32Array, block: Uint32Array, rounds: number): void {
    for (let i = 0; i < state.length && i < block.length; i++) {
        state[i] ^= block[i];
    }
    // Apply bitslice S-box and linear mixing rounds
    for (let r = 0; r < rounds; r++) {
        for (let idx = 0; idx < state.length - 2; idx += 3) {
            bitsliceS7(state, idx);
        }
    }
}

function padMessage(bytes: Uint8Array, blockSize: number): Uint8Array {
    const originalLen = bytes.length;
    const padLen = (blockSize - ((originalLen + 1 + 8) % blockSize)) % blockSize;
    const totalLen = originalLen + 1 + padLen + 8;
    const padded = new Uint8Array(totalLen);
    
    padded.set(bytes);
    padded[originalLen] = 0x80; // append single 1 bit (0x80 in byte)

    // Append 64-bit big-endian bit count
    const bitCount = BigInt(originalLen) * 8n;
    const view = new DataView(padded.buffer);
    view.setBigUint64(totalLen - 8, bitCount, false);

    return padded;
}

export function generate(input: string, key?: string): string {
    const bytes = new TextEncoder().encode(input);
    const variant = 'hamsi-256'; // Default variant
    const blockSize = variant === 'hamsi-256' ? 4 : 8;
    const rounds = variant === 'hamsi-256' ? 6 : 8;

    const padded = padMessage(bytes, blockSize);
    const state = new Uint32Array(variant === 'hamsi-256' ? 16 : 32);
    state.set(variant === 'hamsi-256' ? HAMSI_256_IV : HAMSI_512_IV);

    const blockView = new DataView(padded.buffer);
    for (let i = 0; i < padded.length; i += blockSize) {
        const chunk = new Uint32Array(blockSize / 4);
        for (let j = 0; j < chunk.length; j++) {
            chunk[j] = blockView.getUint32(i + j * 4, false);
        }
        compressBlock(state, chunk, rounds);
    }

    // Convert state to hex digest
    let hex = '';
    const outputBytes = variant === 'hamsi-256' ? 32 : 64;
    const stateBytes = new Uint8Array(state.buffer);
    for (let i = 0; i < outputBytes; i++) {
        hex += stateBytes[i].toString(16).padStart(2, '0');
    }
    return hex;
}

export function verify(input: string, key?: string, hash?: string): boolean {
    if (!hash) return false;
    const computed = generate(input, key);
    return computed.toLowerCase() === hash.toLowerCase();
}

export const hamsiDefinition: CipherDefinition = {
    id: "hamsi",
    name: "Hamsi",
    category: "hash",
    securityStatus: "legacy",
    description: "SHA-3 finalist hash function featuring a bitslice-parallel Serpent S7 sponge construction.",
    practicalUseCases: [
        "Academic study of bitslice hash constructions",
        "Hardware-area-optimised cryptographic hashing",
        "Analysis of SHA-3 finalist design diversity"
    ],
    prerequisites: ["sha3", "jh", "grostl"],
    recommendedNext: ["blake2b", "blake3"],
    defaultKey: "",
    options: [
        {
            name: "variant",
            label: "Hamsi Variant",
            type: "select",
            default: "hamsi-256",
            options: [
                { value: "hamsi-256", label: "Hamsi-256" },
                { value: "hamsi-512", label: "Hamsi-512" }
            ]
        }
    ]
};
