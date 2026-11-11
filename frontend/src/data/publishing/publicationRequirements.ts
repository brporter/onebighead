import type { ExecuteResponse, PublishIntent, PublishRequirement, PublishResolution } from '../../utils/types';
import { isValidSlug } from '../../utils/slugUtils';

export interface PublicationDraft { slug: string; acknowledged: ReadonlySet<string> }

export function requirementKey(requirement: PublishRequirement): string | null {
  switch (requirement.kind) {
    case 'workspace-slug-required': return `workspace:${requirement.workspaceId}`;
    case 'collection-not-public': return `collection:${requirement.collectionId}`;
    case 'category-not-public': return `category:${requirement.categoryId}`;
    case 'unpublish-will-hide-children': return `private:${requirement.entityType}:${requirement.entityId}`;
    default: return null;
  }
}

/** Validation and serialization share one policy; unknown requirements never authorize a write. */
export function resolveRequirements(requirements: PublishRequirement[], draft: PublicationDraft): PublishResolution[] | null {
  const resolutions: PublishResolution[] = [];
  for (const requirement of requirements) {
    const key = requirementKey(requirement);
    if (key === null) return null;
    if (requirement.kind !== 'workspace-slug-required' && !draft.acknowledged.has(key)) return null;
    switch (requirement.kind) {
      case 'workspace-slug-required':
        if (!isValidSlug(draft.slug.trim())) return null;
        resolutions.push({ kind: requirement.kind, slug: draft.slug.trim() });
        break;
      case 'collection-not-public': resolutions.push({ kind: requirement.kind, collectionId: requirement.collectionId }); break;
      case 'category-not-public': resolutions.push({ kind: requirement.kind, categoryId: requirement.categoryId }); break;
      case 'unpublish-will-hide-children':
        resolutions.push({ kind: requirement.kind, entityType: requirement.entityType, entityId: requirement.entityId,
          affectedPublicItems: requirement.affectedPublicItems, affectedPublicCategories: requirement.affectedPublicCategories });
        break;
    }
  }
  return resolutions;
}

export function publicationNotice(action: PublishIntent['action'], response: ExecuteResponse) {
  const verb = action === 'publish' ? 'published' : 'made private';
  const message = response.changed.length === 0 ? 'Visibility updated.' : response.changed.length === 1
    ? `${response.changed[0].name} ${verb}.` : `${response.changed.length} entries ${verb}.`;
  const details = response.promoted.length > 0 ? `Also made public: ${response.promoted.map(entity => entity.name).join(', ')}.` : undefined;
  return { message, details };
}
