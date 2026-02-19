import { Outlet, Link, useParams } from 'react-router-dom';
import { useEffect, useState } from 'react';
import { publicApi, type PublicWorkspace } from '../../api';
import '../../styles/components/PublicLayout.css';

function PublicLayout() {
  const { slug } = useParams<{ slug: string }>();
  const [workspace, setWorkspace] = useState<PublicWorkspace | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!slug) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect -- loading state must be set before async fetch
    setLoading(true);
    publicApi.getWorkspace(slug)
      .then(setWorkspace)
      .catch(() => setError('Workspace not found'))
      .finally(() => setLoading(false));
  }, [slug]);

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
