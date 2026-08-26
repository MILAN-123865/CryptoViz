import * as fc from 'fast-check';

/**
 * Custom fast-check arbitraries for cryptographic input constraints.
 * Uses fast-check v4 compatible APIs.
 */
export const cryptoArbitraries = {
  // General UTF-8 strings including empty strings
  arbitraryUtf8: fc.string(),

  // Alphabetic-only strings for classical ciphers (Caesar, Playfair, Vigenere, etc.)
  arbitraryAlphabetic: fc.string({ unit: 'grapheme' }).map(s => s.replace(/[^a-zA-Z]/g, 'A')),

  // Hexadecimal strings for ciphers requiring hex inputs/keys (fc.hexString in v4)
  arbitraryHex: fc.hexString({ minLength: 2, maxLength: 64 }).filter(s => s.length % 2 === 0),

  // Variable-length keys
  arbitraryKey: fc.string({ minLength: 1, maxLength: 32 }),

  // Printable ASCII strings (for ciphers that require printable chars)
  arbitraryPrintableAscii: fc.string({ minLength: 1, maxLength: 128 }).filter(
    s => s.length > 0 && Array.from(s).every(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126)
  ),

  // Fixed-length 16-byte key (for AES-128)
  arbitrary16ByteKey: fc.string({ minLength: 16, maxLength: 16 }).map(s => {
    let res = '';
    for (let i = 0; i < 16; i++) {
      res += String.fromCharCode(32 + (s.charCodeAt(i) % 95));
    }
    return res;
  }),

  // Fixed-length 8-byte key (for DES)
  arbitrary8ByteKey: fc.string({ minLength: 8, maxLength: 8 }).map(s => {
    let res = '';
    for (let i = 0; i < 8; i++) {
      res += String.fromCharCode(32 + (s.charCodeAt(i) % 95));
    }
    return res;
  }),
};
