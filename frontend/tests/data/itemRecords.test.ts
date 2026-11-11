import { expect, it, vi } from 'vitest';
import { ItemRecords, resolveItemRecords } from '../../src/data/items/ItemRecords';
import { createMockItem } from '../testUtils/factories';

const item = createMockItem();

it('publishes immutable snapshots, preserves independent records, and unsubscribes', () => {
  const records = new ItemRecords();
  const original = records.getSnapshot();
  const listener = vi.fn();
  const unsubscribe = records.subscribe(listener);
  records.write(1, item);
  const first = records.getSnapshot();
  expect(first.get(1)).toBe(item);
  expect(original.size).toBe(0);
  records.write(2, { ...item, id: 2 });
  expect(first.size).toBe(1);
  expect(records.getSnapshot().size).toBe(2);
  expect(listener).toHaveBeenCalledTimes(2);
  unsubscribe();
  records.write(1, null);
  expect(listener).toHaveBeenCalledTimes(2);
  expect(records.getSnapshot().get(1)).toBeNull();
});

it('lets the latest read for an item win, independently of other items', () => {
  const records = new ItemRecords();
  const old = records.beginRead(1);
  const current = records.beginRead(1);
  const other = records.beginRead(2);
  expect(records.accept([[1, item]], old)).toBe(false);
  expect(records.accept([[2, { ...item, id: 2 }]], other)).toBe(true);
  expect(records.accept([[1, item]], current)).toBe(true);
  expect(records.getSnapshot().get(1)).toBe(item);
});

it('accepts list records without overwriting later detail requests or confirmed deletions', () => {
  const records = new ItemRecords();
  const list = records.beginRead();
  const detail = records.beginRead(1);
  records.write(2, null);
  expect(records.accept([[1, item], [2, { ...item, id: 2 }], [3, { ...item, id: 3 }]], list)).toBe(true);
  expect(records.getSnapshot().has(1)).toBe(false);
  expect(records.getSnapshot().get(2)).toBeNull();
  expect(records.getSnapshot().get(3)?.id).toBe(3);
  records.accept([[1, item]], detail);
  expect(resolveItemRecords([item, { ...item, id: 2 }, { ...item, id: 4 }], records.getSnapshot())).toEqual([item, { ...item, id: 4 }]);
});

it('prevents old reads from replacing a write, without mutating the caller’s list', () => {
  const records = new ItemRecords();
  const list = [item];
  const request = records.beginRead(1);
  const saved = { ...item, name: 'Saved' };
  records.write(1, saved);
  expect(records.accept([[1, item]], request)).toBe(false);
  expect(resolveItemRecords(list, records.getSnapshot())).toEqual([saved]);
  expect(list).toEqual([item]);
});

it('invalidates outstanding reads while preserving display data and accepts subsequent requests', () => {
  const records = new ItemRecords();
  records.write(1, item);
  const pending = records.beginRead(1);
  records.invalidate();
  expect(records.accept([[1, null]], pending)).toBe(false);
  expect(records.getSnapshot().get(1)).toBe(item);
  expect(records.accept([[1, null]], records.beginRead(1))).toBe(true);
  expect(records.getSnapshot().get(1)).toBeNull();
});

it('does not publish an empty batch', () => {
  const records = new ItemRecords();
  const listener = vi.fn();
  records.subscribe(listener);
  const original = records.getSnapshot();
  expect(records.accept([], records.beginRead())).toBe(false);
  expect(records.getSnapshot()).toBe(original);
  expect(listener).not.toHaveBeenCalled();
});
