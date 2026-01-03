import type { Collection } from '../types';

const collections = [
  { collectionId: 1, name: 'Classic Computers', tenantId: 1 },
  { collectionId: 2, name: 'Comic Books', tenantId: 1 },
  { collectionId: 3, name: 'Patches and Pins', tenantId: 2 }
] as const satisfies readonly Collection[];

export default collections;

