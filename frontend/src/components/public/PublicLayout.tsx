import { Outlet, Link, useParams } from 'react-router-dom';
import { useCallback } from 'react';
import { publicApi, type PublicWorkspace } from '../../api';
import { useAsyncData } from '../../utils/useAsyncData';
import '../../styles/components/PublicLayout.css';

function PublicLayout() {
  const { slug } = useParams<{ slug: string }>();

  const fetchWorkspace = useCallback(
    () => publicApi.getWorkspace(slug!),
    [slug],
  );
  const { data: workspace, loading, error } = useAsyncData<PublicWorkspace>(
    slug ? fetchWorkspace : null,
  );

  if (loading) {
    return (
      <div className="publicLayout">
        <div className="publicLayout__loading">Loading...</div>
      </div>
    );
  }

  if (error || !workspace) {
    return (
      <div className="publicLayout">
        <div className="publicLayout__error">
          <h1>Not Found</h1>
          <p>This workspace doesn't exist or isn't publicly accessible.</p>
        </div>
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
          <a href="/signin" className="publicLayout__signIn">Sign in</a>
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
