import '../../styles/components/publish.css';

interface PublishButtonProps {
  onPublish: () => void;
  className?: string;
}

export function PublishButton({ onPublish, className }: PublishButtonProps) {
  return (
    <button
      type="button"
      className={`publish-btn${className ? ` ${className}` : ''}`}
      onClick={(e) => {
        e.stopPropagation();
        onPublish();
      }}
    >
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 4l-1.41 1.41L16.17 11H4v2h12.17l-5.58 5.59L12 20l8-8z" transform="rotate(-90 12 12)" />
      </svg>
      Publish
    </button>
  );
}
