/**
 * Core cipher types — authoritative reference for all cipher implementations.
 * Every file in lib/cipher/ must use these types.
 *
 * @see CIPHER_ENGINE.md "Shared types" section
 */

import type { DataProvenanceMetadata } from "../provenance";

export type Encoding = "utf8" | "hex" | "base64" | "binary";

export type CipherDirection = "encrypt" | "decrypt";

export interface CipherStep {
  index: number;
  label: string;
  sublabel?: string;
  inputState: string;
  outputState: string;
  highlight?: number[];
  matrix?: string[][];
  table?: { key: string; value: string }[];
  note?: string;
  isMilestone?: boolean;
}

export interface CipherResult {
  output: string;
  outputEncoding: Encoding;
  steps: CipherStep[];
  metadata: CipherMetadata;
  durationMs: number;
  provenance?: DataProvenanceMetadata;
}

export interface CipherMetadata {
  name: string;
  keySize?: number;
  blockSize?: number;
  rounds?: number;
  modeOfOperation?: string;
  securityStatus:
    | "secure"
    | "legacy"
    | "deprecated"
    | "broken"
    | "mock";

  breakingComplexity?: string;
  yearDesigned?: number;
  standardBody?: string;
  securityWarning?: string;
  provenance: DataProvenanceMetadata;
}

export interface CipherOptions {
  mode?: string;
  padding?: string;
  encoding?: Encoding;
  iv?: string;
  hash?: string;
  keyLength?: number;
  info?: string;
  instrument?: boolean;
  signal?: AbortSignal;
  hexInput?: boolean;
  rounds?: number;
  N?: number;
  r?: number;
  p?: number;
  dkLen?: number;
  salt?: string;
  iterations?: number;
  [key: string]: unknown;
}

export interface TestVector {
  input: string;
  key: string;
  expected: string;
  expectedDecrypt?: string;
  description?: string;
  skipEncrypt?: boolean;
  skipDecrypt?: boolean;
  options?: Record<string, unknown>;
}
