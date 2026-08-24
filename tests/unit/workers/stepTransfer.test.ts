import { describe, expect, it } from 'vitest'
import type { CipherStep } from '@/lib/cipher/types'
import {
  decodeCipherSteps,
  encodeCipherSteps,
  WORKER_STEP_TRANSFER_THRESHOLD,
} from '@/lib/workers/stepTransfer'

const step: CipherStep = {
  index: 0,
  label: 'Round 1',
  inputState: '00',
  outputState: 'ff',
  highlight: [0],
  note: 'Example step',
}

describe('cipher step transfer protocol', () => {
  it('uses the large-trace transfer threshold', () => {
    expect(WORKER_STEP_TRANSFER_THRESHOLD).toBe(100)
  })

  it('round-trips cipher steps through a transferable byte buffer', () => {
    const steps = Array.from({ length: 500 }, (_, index) => ({
      ...step,
      index,
      label: `Round ${index + 1}`,
    }))

    const encoded = encodeCipherSteps(steps)
    expect(encoded).toBeInstanceOf(Uint8Array)
    expect(encoded.byteLength).toBeGreaterThan(0)

    const decoded = decodeCipherSteps(encoded.buffer)
    expect(decoded).toEqual(steps)
  })

  it('rejects malformed transferred payloads', () => {
    const malformed = new TextEncoder().encode('{"steps":{}}')
    expect(() => decodeCipherSteps(malformed)).toThrow(
      'Invalid transferred cipher steps payload.',
    )
  })
})
