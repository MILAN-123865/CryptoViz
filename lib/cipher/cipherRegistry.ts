import { KalynaEngine } from './kalyna/kalynaEngine';
import { BaseCipher } from './baseCipher';

export class CipherRegistry {
  private ciphers: Map<string, BaseCipher> = new Map();

  constructor() {
    this.register('kalyna', new KalynaEngine());
  }

  register(name: string, instance: BaseCipher): void {
    this.ciphers.set(name, instance);
  }

  get(name: string): BaseCipher | undefined {
    return this.ciphers.get(name);
  }
}

export const globalCipherRegistry = new CipherRegistry();
