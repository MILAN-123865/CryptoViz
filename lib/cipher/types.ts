/**
 * Core cipher types — authoritative reference for all cipher implementations.
 * Every file in lib/cipher/ must use these types.
 *
 * @see CIPHER_ENGINE.md "Shared types" section
 */

import type { DataProvenanceMetadata } from "../provenance";

/**
 * Encoding cipher-engine utility export.
 *
 * This API is intentionally documented at the engine boundary so callers
 * can understand the input contract without opening the implementation.
 * @returns The operation result produced by the cipher engine.
 * @see https://csrc.nist.gov/pubs/fips/46-3/final — FIPS 46-3.
 */
export type Encoding = "utf8" | "hex" | "base64" | "binary";

/**
 * Cipher Name cipher-engine utility export.
 *
 * This API is intentionally documented at the engine boundary so callers
 * can understand the input contract without opening the implementation.
 * @returns The operation result produced by the cipher engine.
 * @see https://csrc.nist.gov/pubs/fips/46-3/final — FIPS 46-3.
 */
export type CipherName = string;

/**
 * Cipher Direction cipher-engine utility export.
 *
 * This API is intentionally documented at the engine boundary so callers
 * can understand the input contract without opening the implementation.
 * @returns The operation result produced by the cipher engine.
 * @see https://csrc.nist.gov/pubs/fips/46-3/final — FIPS 46-3.
 */
export type CipherDirection = "encrypt" | "decrypt";

/**
 * Cipher Step cipher-engine utility export.
 *
 * This API is intentionally documented at the engine boundary so callers
 * can understand the input contract without opening the implementation.
 * @returns The operation result produced by the cipher engine.
 * @see https://csrc.nist.gov/pubs/fips/46-3/final — FIPS 46-3.
 */
export interface CipherStep {
  index: number;
  label: string;
  sublabel?: string;
  inputState: string;
  outputState: string;
  highlight?: number[];
  matrix?: string[][];
  table?: { key: string; value: string }[];
  sboxInspection?: {
    family: string;
    inputValue: string;
    desIndex?: number;
    serpentIndex?: number;
  };
  note?: string;
  isMilestone?: boolean;
}

/**
 * Cipher Result cipher-engine utility export.
 *
 * This API is intentionally documented at the engine boundary so callers
 * can understand the input contract without opening the implementation.
 * @returns The operation result produced by the cipher engine.
 * @see https://csrc.nist.gov/pubs/fips/46-3/final — FIPS 46-3.
 */
export interface CipherResult {
  output: string;
  outputEncoding: Encoding;
  steps: CipherStep[];
  metadata: CipherMetadata;
  durationMs: number;
  provenance?: DataProvenanceMetadata;
}

/**
 * Cipher Metadata cipher-engine utility export.
 *
 * This API is intentionally documented at the engine boundary so callers
 * can understand the input contract without opening the implementation.
 * @returns The operation result produced by the cipher engine.
 * @see https://csrc.nist.gov/pubs/fips/46-3/final — FIPS 46-3.
 */
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
    | "mock"
    | "recommended"
    | "experimental";

  breakingComplexity?: string;
  yearDesigned?: number;
  standardBody?: string;
  securityWarning?: string;
  provenance?: DataProvenanceMetadata;
}

/**
 * Cipher Options cipher-engine utility export.
 *
 * This API is intentionally documented at the engine boundary so callers
 * can understand the input contract without opening the implementation.
 * @returns The operation result produced by the cipher engine.
 * @see https://csrc.nist.gov/pubs/fips/46-3/final — FIPS 46-3.
 */
export interface CipherOptions {
  mode?: string;
  padding?: boolean | string;
  encoding?: Encoding;
  iv?: string;
  hash?: string;
  keyLength?: number;
  info?: string;
  instrument?: boolean;
  preserveFormatting?: boolean;
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

/**
 * Test Vector cipher-engine utility export.
 *
 * This API is intentionally documented at the engine boundary so callers
 * can understand the input contract without opening the implementation.
 * @returns The operation result produced by the cipher engine.
 * @see https://csrc.nist.gov/pubs/fips/46-3/final — FIPS 46-3.
 */
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
