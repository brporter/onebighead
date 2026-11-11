import type { Item } from '../../utils/types';

/** Workspace-scoped item identity and read ordering, independent of list membership. */
export class ItemRecords {
  private snapshot: ReadonlyMap<number, Item | null> = new Map();
  private readonly listeners = new Set<() => void>();
  private readonly revisions = new Map<number, number>();
  private clock = 0;
  private minimum = 0;

  getSnapshot = () => this.snapshot;
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };

  beginRead(id?: number): number {
    const revision = ++this.clock;
    if (id !== undefined) this.revisions.set(id, revision);
    return revision;
  }

  invalidate(): void {
    this.minimum = ++this.clock;
  }

  accept(entries: ReadonlyArray<readonly [number, Item | null]>, revision: number): boolean {
    if (revision < this.minimum) return false;
    const next = new Map(this.snapshot);
    let changed = false;
    for (const [id, item] of entries) {
      if (revision < (this.revisions.get(id) ?? 0)) continue;
      this.revisions.set(id, revision);
      next.set(id, item);
      changed = true;
    }
    if (changed) {
      this.snapshot = next;
      this.listeners.forEach(listener => listener());
    }
    return changed;
  }

  write(id: number, item: Item | null): void {
    this.accept([[id, item]], this.beginRead(id));
  }

}

export function resolveItemRecords(items: Item[], snapshot: ReadonlyMap<number, Item | null>): Item[] {
  return items.flatMap(item => {
    const current = snapshot.get(item.id!);
    return current === null ? [] : [current ?? item];
  });
}
