/**
 * Unified Trace Schema and Replay Engine - Public API
 */

export type {
  AlgorithmTrace,
  TraceStep,
  TerminalState,
  ExecutionPhase,
  ValidatedTrace,
  InvalidTrace,
} from './traceSchema';

export { UnifiedReplayEngine } from './replayEngine';
export type { ReplayState, ReplayPosition } from './replayEngine';

export {
  validateTrace,
  isValidTransition,
  performDeepValidation,
} from './validators';

export {
  serializeTrace,
  deserializeTrace,
  exportTraceAsFile,
  importTraceFromFile,
  compressTrace,
  getTraceSize,
} from './serialization';