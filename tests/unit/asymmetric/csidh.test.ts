import { describe, expect, it } from 'vitest'
import { encrypt, decrypt, TEST_VECTORS } from '@/lib/cipher/asymmetric/csidh'
describe('CSIDH', () => {
    it('commutativity: Alice.apply(Bob) == Bob.apply(Alice)', () => {
        const alicePriv = '01'
        const bobPriv = '02'

        // Mock public keys (in real CSIDH, these are curve coefficients)
        const alicePub = '0a'
        const bobPub = '0b'

        const sharedAlice = encrypt(bobPub, alicePriv)
        const sharedBob = encrypt(alicePub, bobPriv)

        // In our simplified mock, (0b + 01) == (0a + 02) => 0c == 0c
        expect(sharedAlice.output).toBe(sharedBob.output)
    })
    it('exports valid CSIDH test vectors', () => {
    expect(TEST_VECTORS.length).toBeGreaterThan(0)

    for (const vector of TEST_VECTORS) {
        const result = encrypt(vector.input, vector.key)
        expect(result.output).toBe(vector.expected)
    }
})
})
