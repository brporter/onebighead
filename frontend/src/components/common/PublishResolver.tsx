import { useState, useEffect, useCallback } from 'react';
import { publishManagerApi } from '../../api/publishManager';
import { useToast } from '../../contexts/useToast';
import { useUser } from '../../contexts/useUser';
import { isValidSlug } from '../../utils/slugUtils';
import type {
  PublishIntent,
  PublishRequirement,
  PublishResolution,
  PreflightResponse,
  ExecuteResponse,
} from '../../utils/types';
import '../../styles/components/publish-resolver.css';

interface PublishResolverProps {
  intent: PublishIntent | null;
  onClearIntent: () => void;
  onComplete: () => void;
}

export function PublishResolver({ intent, onClearIntent, onComplete }: PublishResolverProps) {
  const { showToast } = useToast();
  const { user, refetch: refetchUser } = useUser();
  const workspaceId = user?.activeWorkspace?.workspaceId;

  const [requirements, setRequirements] = useState<PublishRequirement[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [showModal, setShowModal] = useState(false);

  // Resolution state
  const [slugValue, setSlugValue] = useState('');
  const [acknowledgedCollections, setAcknowledgedCollections] = useState<Set<number>>(new Set());
  const [acknowledgedCategories, setAcknowledgedCategories] = useState<Set<number>>(new Set());
  const [acknowledgedUnpublish, setAcknowledgedUnpublish] = useState<Set<string>>(new Set());

  const resetState = useCallback(() => {
    setRequirements([]);
    setError(null);
    setSlugValue('');
    setAcknowledgedCollections(new Set());
    setAcknowledgedCategories(new Set());
    setAcknowledgedUnpublish(new Set());
    setShowModal(false);
    setLoading(false);
  }, []);

  const buildToastMessage = useCallback((response: ExecuteResponse): string => {
    if (response.changed.length === 0) return 'Done.';
    if (response.changed.length === 1) {
      const action = intent?.action === 'publish' ? 'published' : 'unpublished';
      return `${response.changed[0].name} ${action}.`;
    }
    const action = intent?.action === 'publish' ? 'published' : 'unpublished';
    return `${response.changed.length} items ${action}.`;
  }, [intent]);

  const buildToastDetails = useCallback((response: ExecuteResponse): string | undefined => {
    if (response.promoted.length === 0) return undefined;
    const names = response.promoted.map(p => `'${p.name}'`).join(', ');
    return `Promoted: ${names} are now visible in your gallery.`;
  }, []);

  const doExecute = useCallback(async (resolutions: PublishResolution[]) => {
    if (!intent || !workspaceId) return;

    setLoading(true);
    try {
      const result = await publishManagerApi.execute(workspaceId, {
        action: intent.action,
        entities: intent.entities,
        resolutions,
      });

      if (!result.success) {
        setError(result.error ?? 'Publish failed');
        if (result.requirements) {
          setRequirements(result.requirements);
        }
        setLoading(false);
        return;
      }

      if (result.workspaceSlugSet) {
        await refetchUser();
      }

      showToast(buildToastMessage(result), buildToastDetails(result));
      resetState();
      onClearIntent();
      onComplete();
    } catch {
      setError('An unexpected error occurred');
      setLoading(false);
    }
  }, [intent, workspaceId, refetchUser, showToast, buildToastMessage, buildToastDetails, resetState, onClearIntent, onComplete]);

  // Run preflight when intent changes
  useEffect(() => {
    if (!intent || !workspaceId) {
      resetState();
      return;
    }

    let cancelled = false;

    async function runPreflight() {
      setLoading(true);
      setError(null);

      try {
        const result: PreflightResponse = await publishManagerApi.preflight(
          workspaceId!,
          intent!.action,
          intent!.entities,
        );

        if (cancelled) return;

        if (result.ready) {
          await doExecute([]);
        } else {
          setRequirements(result.requirements);
          setShowModal(true);
          setLoading(false);
        }
      } catch {
        if (!cancelled) {
          setError('Failed to check publish requirements');
          setShowModal(true);
          setLoading(false);
        }
      }
    }

    runPreflight();
    return () => { cancelled = true; };
  }, [intent, workspaceId]); // eslint-disable-line react-hooks/exhaustive-deps

  const allResolved = useCallback((): boolean => {
    for (const req of requirements) {
      switch (req.kind) {
        case 'workspace-slug-required':
          if (!isValidSlug(slugValue)) return false;
          break;
        case 'collection-not-public':
          if (!acknowledgedCollections.has(req.collectionId)) return false;
          break;
        case 'category-not-public':
          if (!acknowledgedCategories.has(req.categoryId)) return false;
          break;
        case 'unpublish-will-hide-children':
          if (!acknowledgedUnpublish.has(`${req.entityType}-${req.entityId}`)) return false;
          break;
      }
    }
    return true;
  }, [requirements, slugValue, acknowledgedCollections, acknowledgedCategories, acknowledgedUnpublish]);

  const buildResolutions = useCallback((): PublishResolution[] => {
    const resolutions: PublishResolution[] = [];
    for (const req of requirements) {
      switch (req.kind) {
        case 'workspace-slug-required':
          resolutions.push({ kind: 'workspace-slug-required', slug: slugValue });
          break;
        case 'collection-not-public':
          resolutions.push({ kind: 'collection-not-public', collectionId: req.collectionId });
          break;
        case 'category-not-public':
          resolutions.push({ kind: 'category-not-public', categoryId: req.categoryId });
          break;
        case 'unpublish-will-hide-children':
          resolutions.push({ kind: 'unpublish-will-hide-children', entityType: req.entityType, entityId: req.entityId });
          break;
      }
    }
    return resolutions;
  }, [requirements, slugValue]);

  const handleSubmit = useCallback(() => {
    doExecute(buildResolutions());
  }, [doExecute, buildResolutions]);

  const handleCancel = useCallback(() => {
    resetState();
    onClearIntent();
  }, [resetState, onClearIntent]);

  const toggleCollection = useCallback((id: number) => {
    setAcknowledgedCollections(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);

  const toggleCategory = useCallback((id: number) => {
    setAcknowledgedCategories(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);

  const toggleUnpublish = useCallback((key: string) => {
    setAcknowledgedUnpublish(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }, []);

  if (!showModal || !intent) return null;

  const isPublish = intent.action === 'publish';
  const title = isPublish ? 'Publish' : 'Make Private';

  return (
    <div className="publish-resolver__overlay" onClick={handleCancel}>
      <div className="publish-resolver" onClick={e => e.stopPropagation()}>
        <div className="publish-resolver__header">
          <h2 className="publish-resolver__title">{title}</h2>
        </div>

        <div className="publish-resolver__body">
          {error && <div className="publish-resolver__error" role="alert">{error}</div>}

          {requirements.map((req, i) => {
            switch (req.kind) {
              case 'workspace-slug-required':
                return (
                  <div key={i} className="publish-resolver__slug-group">
                    <p className="publish-resolver__slug-label">
                      Your workspace needs a public gallery URL before publishing.
                    </p>
                    <label htmlFor="publish-slug-input" className="publish-resolver__slug-label">Gallery URL</label>
                    <input
                      id="publish-slug-input"
                      type="text"
                      className="publish-resolver__slug-input"
                      value={slugValue}
                      onChange={e => setSlugValue(e.target.value)}
                      placeholder="my-collection"
                      maxLength={50}
                    />
                    <p className="publish-resolver__slug-preview">/public/{slugValue}</p>
                  </div>
                );

              case 'collection-not-public':
                return (
                  <div key={i} className="publish-resolver__requirement">
                    <input
                      type="checkbox"
                      id={`ack-col-${req.collectionId}`}
                      checked={acknowledgedCollections.has(req.collectionId)}
                      onChange={() => toggleCollection(req.collectionId)}
                    />
                    <label htmlFor={`ack-col-${req.collectionId}`}>
                      Collection &apos;{req.collectionName}&apos; will be made public
                    </label>
                  </div>
                );

              case 'category-not-public':
                return (
                  <div key={i} className="publish-resolver__requirement">
                    <input
                      type="checkbox"
                      id={`ack-cat-${req.categoryId}`}
                      checked={acknowledgedCategories.has(req.categoryId)}
                      onChange={() => toggleCategory(req.categoryId)}
                    />
                    <label htmlFor={`ack-cat-${req.categoryId}`}>
                      Category &apos;{req.categoryName}&apos; will be made public
                    </label>
                  </div>
                );

              case 'unpublish-will-hide-children': {
                const key = `${req.entityType}-${req.entityId}`;
                return (
                  <div key={i}>
                    <div className="publish-resolver__impact">
                      Making &apos;{req.entityName}&apos; private will hide{' '}
                      {req.affectedPublicItems} {req.affectedPublicItems === 1 ? 'item' : 'items'}
                      {req.affectedPublicCategories > 0 && (
                        <> and {req.affectedPublicCategories} {req.affectedPublicCategories === 1 ? 'category' : 'categories'}</>
                      )}
                      {' '}from your public gallery. They will reappear if you make this {req.entityType} public again.
                    </div>
                    <div className="publish-resolver__requirement">
                      <input
                        type="checkbox"
                        id={`ack-unpub-${key}`}
                        checked={acknowledgedUnpublish.has(key)}
                        onChange={() => toggleUnpublish(key)}
                      />
                      <label htmlFor={`ack-unpub-${key}`}>I understand</label>
                    </div>
                  </div>
                );
              }

              default:
                return null;
            }
          })}
        </div>

        <div className="publish-resolver__footer">
          <button
            type="button"
            className="modal__button modal__button--secondary"
            onClick={handleCancel}
          >
            Cancel
          </button>
          <button
            type="button"
            className="modal__button modal__button--primary"
            onClick={handleSubmit}
            disabled={!allResolved() || loading}
          >
            {loading ? 'Processing...' : isPublish ? 'Publish' : 'Make Private'}
          </button>
        </div>
      </div>
    </div>
  );
}
