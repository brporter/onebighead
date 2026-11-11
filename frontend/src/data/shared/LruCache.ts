/** A bounded cache with access ordering independent of clock precision. */
export class LruCache<K, V> {
  private readonly entries = new Map<K, V>();

  constructor(private readonly capacity: number) {
    if (!Number.isInteger(capacity) || capacity < 1) {
      throw new RangeError('Cache capacity must be a positive integer');
    }
  }

  get(key: K): V | undefined {
    const value = this.entries.get(key);
    if (this.entries.has(key)) {
      this.entries.delete(key);
      this.entries.set(key, value!);
    }
    return value;
  }

  set(key: K, value: V): void {
    this.entries.delete(key);
    this.entries.set(key, value);
    if (this.entries.size > this.capacity) {
      this.entries.delete(this.entries.keys().next().value!);
    }
  }

  clear(): void {
    this.entries.clear();
  }
}
