import { vi } from 'vitest';
import type { ExecuteResponse, PreflightResponse, PublishRequirement } from '../../src/utils/types';
import type { PublicationRequest, PublicationSessionOptions } from '../../src/data/publishing/publicationSession';

export const request: PublicationRequest = { requestId: 1, workspaceId: 7, action: 'publish', entities: [{ type: 'item', id: 4 }] };
export const collectionRequirement: PublishRequirement = { kind: 'collection-not-public', collectionId: 2, collectionName: 'Books' };
export const requirements: PublishRequirement[] = [
  { kind: 'workspace-slug-required', workspaceId: 7, workspaceName: 'Library' },
  collectionRequirement,
  { kind: 'category-not-public', categoryId: 3, categoryName: 'Classics' },
  { kind: 'unpublish-will-hide-children', entityType: 'category', entityId: 3, entityName: 'Classics', affectedPublicItems: 1, affectedPublicCategories: 1 },
];
export const saved: ExecuteResponse = { success: true, changed: [{ type: 'item', id: 4, name: 'Dune' }], promoted: [] };
export function publicationOptions() {
  return {
    request,
    gateway: {
      preflight: vi.fn<PublicationSessionOptions['gateway']['preflight']>().mockResolvedValue({ ready: false, requirements: [collectionRequirement] } satisfies PreflightResponse),
      execute: vi.fn<PublicationSessionOptions['gateway']['execute']>().mockResolvedValue(saved),
    },
    refresh: vi.fn<PublicationSessionOptions['refresh']>().mockResolvedValue(undefined),
    complete: vi.fn(), dismiss: vi.fn(),
  } satisfies PublicationSessionOptions;
}
