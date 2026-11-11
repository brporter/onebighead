import { useId } from 'react';
import type { PublishRequirement } from '../../utils/types';
import { isValidSlug } from '../../utils/slugUtils';
import { usePublicationSession } from '../../data/publishing/usePublicationSession';
import { requirementKey, resolveRequirements, type PublicationDraft } from '../../data/publishing/publicationRequirements';
import type { PublicationSessionOptions } from '../../data/publishing/publicationSession';
import { ModalDialog } from './ModalDialog';
import '../../styles/components/publish-resolver.css';

export function PublishResolver(options: PublicationSessionOptions) {
  const { state, session } = usePublicationSession(options);
  const { phase, error, requirements, draft, saved } = state;
  const action = options.request.action === 'publish' ? 'Publish' : 'Make private';
  const title = saved ? 'Changes saved' : action;
  const locked = phase === 'saving' || phase === 'refreshing' || phase === 'complete';
  const reviewing = phase === 'review';
  const retrying = phase === 'check-error' || phase === 'execute-error' || phase === 'refresh-error';
  const progress = { checking: 'Checking visibility requirements…', saving: 'Saving visibility changes…', refreshing: 'Refreshing your collection…', complete: 'Visibility updated.' };

  return <ModalDialog label={title} onClose={session.cancel}>
    <section className="modal publish-resolver">
      <header className="modal__header"><h2 className="modal__title">{title}</h2></header>
      <div className="publish-resolver__body" aria-busy={locked || phase === 'checking'}>
        {(phase === 'checking' || locked) && <p role="status">{progress[phase as keyof typeof progress]}</p>}
        {error && <p className="modal__error" role="alert">{error}</p>}
        {phase === 'refresh-error' && <p>Your visibility changes were saved. Retry refreshing to see the updated collection.</p>}
        {(reviewing || phase === 'saving') && <>
          <p className="publish-resolver__intro">Review these changes before continuing.</p>
          <fieldset className="publish-resolver__requirements" aria-label="Required visibility changes" disabled={!reviewing}>
            {requirements.map((requirement, index) => <Requirement key={index} requirement={requirement} draft={draft}
              setSlug={session.setSlug} toggle={session.toggle} />)}
          </fieldset>
        </>}
      </div>
      <footer className="modal__footer publish-resolver__footer">
        <button type="button" className="modal__button modal__button--secondary" disabled={locked} onClick={session.cancel}>
          {saved ? 'Close' : 'Cancel'}
        </button>
        {reviewing && <button type="button" className="modal__button modal__button--primary"
          disabled={resolveRequirements(requirements, draft) === null} onClick={() => void session.submit()}>{action}</button>}
        {retrying && <button type="button" className="modal__button modal__button--primary" onClick={() => void session.retry()}>
          {saved ? 'Retry refresh' : 'Check again'}
        </button>}
      </footer>
    </section>
  </ModalDialog>;
}

function Requirement({ requirement, draft, setSlug, toggle }: {
  requirement: PublishRequirement; draft: PublicationDraft; setSlug: (value: string) => void; toggle: (key: string) => void;
}) {
  const id = useId();
  const key = requirementKey(requirement);
  if (key === null) return <p role="alert">This visibility requirement is not supported. Close this dialog and reload the application.</p>;
  if (requirement.kind === 'workspace-slug-required') {
    const invalid = draft.slug.length > 0 && !isValidSlug(draft.slug.trim());
    return <div className="publish-resolver__slug-group">
      <p><strong>{requirement.workspaceName}</strong> needs a public gallery URL before publishing.</p>
      <label className="modal__label" htmlFor={id}>Gallery URL</label>
      <input id={id} className="modal__input" value={draft.slug} onChange={event => setSlug(event.target.value)}
        placeholder="my-collection" autoCapitalize="none" autoCorrect="off" spellCheck={false} maxLength={50}
        aria-describedby={`${id}-hint ${id}-preview`} aria-invalid={invalid} />
      <p id={`${id}-hint`} className="publish-resolver__hint">Use 3–50 lowercase letters, numbers, or single hyphens between words.</p>
      <p id={`${id}-preview`} className="publish-resolver__hint">/public/{draft.slug.trim() || 'my-collection'}</p>
    </div>;
  }
  const impact = requirement.kind === 'unpublish-will-hide-children' ? requirement : null;
  const label = requirement.kind === 'collection-not-public' ? `Make collection “${requirement.collectionName}” public`
    : requirement.kind === 'category-not-public' ? `Make category “${requirement.categoryName}” public`
    : `I understand the impact on “${requirement.entityName}”`;
  return <div className="publish-resolver__requirement">
    {impact && <p id={`${id}-impact`} className="publish-resolver__impact">
      Making <strong>{impact.entityName}</strong> private will hide {impact.affectedPublicItems} {impact.affectedPublicItems === 1 ? 'item' : 'items'}
      {impact.affectedPublicCategories > 0 && <> and {impact.affectedPublicCategories} {impact.affectedPublicCategories === 1 ? 'category' : 'categories'}</>}
      {' '}from your public gallery. Their visibility settings will be preserved.
    </p>}
    <label className="publish-resolver__acknowledgment" htmlFor={id}>
      <input id={id} type="checkbox" checked={draft.acknowledged.has(key)} onChange={() => toggle(key)}
        aria-describedby={impact ? `${id}-impact` : undefined} />
      <span>{label}</span>
    </label>
  </div>;
}
