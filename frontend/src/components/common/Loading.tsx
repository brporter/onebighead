interface LoadingProps {
  message?: string;
  size?: 'sm' | 'md' | 'lg';
  inline?: boolean;
}

export function Loading({ message = 'Loading...', size = 'md', inline = false }: LoadingProps) {
  const spinnerClass = `spinner${size !== 'md' ? ` spinner--${size}` : ''}`;

  if (inline) {
    return (
      <span className="loading loading--inline">
        <span className={spinnerClass} aria-hidden="true" />
        {message && <span className="loading__text">{message}</span>}
      </span>
    );
  }

  return (
    <div className="loading" role="status" aria-live="polite">
      <span className={spinnerClass} aria-hidden="true" />
      {message && <p className="loading__text">{message}</p>}
    </div>
  );
}
