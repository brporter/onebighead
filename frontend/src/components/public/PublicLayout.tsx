import { Outlet, Link, useParams } from 'react-router-dom';
import { useCallback } from 'react';
import { publicApi, type PublicWorkspace } from '../../api';
import { useAsyncData } from '../../utils/useAsyncData';
import { useUser } from '../../contexts/useUser';
import { ContentState } from '../common/ContentState';
import '../../styles/components/PublicLayout.css';

function PublicLayout() {
  const { slug } = useParams<{ slug: string }>();
  const { user, loading: userLoading } = useUser();

  const fetchWorkspace = useCallback(
    (signal: AbortSignal) => publicApi.getWorkspace(slug!, { signal }),
    [slug],
  );
  const { data: workspace, loading, error } = useAsyncData<PublicWorkspace>(
    slug ? fetchWorkspace : null,
  );

  if (loading) {
    return (
      <div className="publicLayout">
        <ContentState kind="loading" title="Loading workspace…" />
      </div>
    );
  }

  if (error || !workspace) {
    return (
      <div className="publicLayout">
        <ContentState kind="error" title="Workspace unavailable">
          {error || "This workspace doesn't exist or isn't publicly accessible."}
        </ContentState>
      </div>
    );
  }

  return (
    <div className="publicLayout">
      <header className="publicLayout__header">
        <div className="publicLayout__headerContent">
          <Link to={`/public/${slug}`} className="publicLayout__brand">
            {workspace.name}
          </Link>
          {!userLoading && (user ? (
            <a href="/collections" className="publicLayout__signIn">My Collections</a>
          ) : (
            <a href="/signin" className="publicLayout__signIn">Sign in</a>
          ))}
        </div>
      </header>
      <main className="publicLayout__main">
        <Outlet context={{ workspace }} />
      </main>
      <footer className="publicLayout__footer">
        <div className="publicLayout__footerContent">
          <span className="publicLayout__footerText">Powered by OneBigHead</span>
        </div>
      </footer>
    </div>
  );
}

export default PublicLayout;
