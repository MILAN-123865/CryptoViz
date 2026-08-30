import { describe, expect, it } from 'vitest'
import { encrypt, decrypt, TEST_VECTORS, getCastryckDecruAttackSummary } from '@/lib/cipher/asymmetric/sidh'

describe('SIDH', () => {
    it('exports test vectors', () => expect(TEST_VECTORS.length).toBeGreaterThan(0))

    it('metadata flags broken status unconditionally', () => {
        const result = encrypt('01', 'pub,priv')
        expect(result.metadata.securityStatus).toBe('broken')
        expect(result.metadata.breakingComplexity).toContain('Castryck')
        expect(result.metadata.breakingComplexity).toContain('Decru')
    })

    it('instrumentation explains the break mechanism', () => {
        const result = encrypt('01', 'pub,priv', { instrument: true })
        const breakNote = result.steps.find(s => s.note?.includes('Castryck'))
        expect(breakNote).toBeDefined()
        expect(breakNote?.note).toContain('torsion')
    })

    it('metadata includes explicit securityWarning about the Castryck-Decru attack', () => {
        const result = encrypt('01', 'pub,priv')
        expect(result.metadata.securityWarning).toContain('Castryck-Decru key-recovery attack')
    })

    it('getCastryckDecruAttackSummary exposes Eurocrypt 2023 details and DOI link', () => {
        const summary = getCastryckDecruAttackSummary()
        expect(summary.authors).toContain('Wouter Castryck')
        expect(summary.authors).toContain('Thomas Decru')
        expect(summary.venue).toContain('Eurocrypt 2023')
        expect(summary.doiUrl).toContain('2022/975')
    })
})
