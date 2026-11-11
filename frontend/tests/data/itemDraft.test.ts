import { expect, it } from 'vitest';
import { createItemDraft, createItemProperty, itemFromDraft, sameItemDraft, type ItemDraft } from '../../src/data/items/itemDraft';
import { createEmptyItem } from '../../src/utils/itemUtils';
import { UserFlag, type Item } from '../../src/utils/types';

it('creates distinct session identities for identical properties without changing persisted data', () => {
  const property = { category: 'Specs', name: 'Voltage', value: '12V' };
  const item = { ...createEmptyItem(7, 2, 3), properties: [property, property], userFlag: UserFlag.Want };
  const draft = createItemDraft(item);
  const secondSession = createItemDraft(item);
  const ids = [...draft.properties, ...secondSession.properties].map(row => row.id);
  expect(new Set(ids).size).toBe(4);
  expect(draft.userFlag).toBe(UserFlag.Want);
  expect(draft.properties[0]).toEqual({ ...property, id: expect.any(String) });
  expect(draft.properties[0]).not.toBe(property);
  expect(itemFromDraft(draft)).toEqual(item);
  expect(property).not.toHaveProperty('id');
});

it('normalizes legacy missing arrays and relationship and creates empty new rows', () => {
  const legacy = { ...createEmptyItem(null, 2, 3), properties: undefined, images: undefined, userFlag: undefined } as unknown as Item;
  expect(createItemDraft(legacy)).toMatchObject({ properties: [], images: [], userFlag: UserFlag.Have });
  expect(createItemProperty()).toEqual({ category: '', name: '', value: '', id: expect.any(String) });
});

it('serializes only property data, preserving order, duplicates, whitespace and values', () => {
  const draft = createItemDraft({ ...createEmptyItem(7, 2, 3), name: '  Camera  ', properties: [
    { category: '', name: '', value: '  handwritten note  ' },
    { category: 'Specs', name: 'Color', value: 'Blue' },
  ] });
  draft.properties.reverse();
  const result = itemFromDraft(draft);
  expect(result.name).toBe('Camera');
  expect(result.properties).toEqual([
    { category: 'Specs', name: 'Color', value: 'Blue' },
    { category: '', name: '', value: '  handwritten note  ' },
  ]);
  expect(result.properties.every(row => !('id' in row))).toBe(true);
  expect(draft.name).toBe('  Camera  ');
});

it('compares editable content without treating new row IDs or server metadata as edits', () => {
  const item = { ...createEmptyItem(1, 2, 3), properties: [{ category: 'Specs', name: 'Color', value: 'Red' }], images: [{ url: '/one.png', alt: 'Front' }] };
  const original = createItemDraft(item);
  const other = createItemDraft({ ...item, effectiveIsPublic: !item.effectiveIsPublic });
  expect(other.properties[0].id).not.toBe(original.properties[0].id);
  expect(sameItemDraft(original, other)).toBe(true);
});

it.each<(draft: ItemDraft) => ItemDraft>([
  draft => ({ ...draft, name: 'Renamed' }),
  draft => ({ ...draft, name: ` ${draft.name} ` }),
  draft => ({ ...draft, summary: 'Changed summary' }),
  draft => ({ ...draft, description: 'Changed description' }),
  draft => ({ ...draft, categoryId: 99 }),
  draft => ({ ...draft, userFlag: UserFlag.Want }),
  draft => ({ ...draft, properties: draft.properties.map(row => ({ ...row, category: 'Details' })) }),
  draft => ({ ...draft, properties: draft.properties.map(row => ({ ...row, name: 'Shade' })) }),
  draft => ({ ...draft, properties: draft.properties.map(row => ({ ...row, value: 'Blue' })) }),
  draft => ({ ...draft, properties: [...draft.properties].reverse() }),
  draft => ({ ...draft, properties: [] }),
  draft => ({ ...draft, properties: [...draft.properties, createItemProperty()] }),
  draft => ({ ...draft, images: draft.images.map(image => ({ ...image, url: '/new.png' })) }),
  draft => ({ ...draft, images: draft.images.map(image => ({ ...image, alt: 'Changed description' })) }),
  draft => ({ ...draft, images: [...draft.images].reverse() }),
  draft => ({ ...draft, images: [] }),
])('detects each editable field, row order and additions/removals (%#)', change => {
  const original = createItemDraft({ ...createEmptyItem(1, 2, 3), properties: [
    { category: 'Specs', name: 'Color', value: 'Red' }, { category: 'Specs', name: 'Size', value: 'Small' },
  ], images: [{ url: '/front.png', alt: 'Front' }, { url: '/back.png', alt: 'Back' }] });
  expect(sameItemDraft(original, change(original))).toBe(false);
});
