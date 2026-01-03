interface BackNavProps {
  label: string;
  onClick: () => void;
}

function BackNav({ label, onClick }: BackNavProps) {
  return (
    <nav className="mobileNav">
      <button
        type="button"
        className="mobileNav__back"
        onClick={onClick}
      >
        ← {label}
      </button>
    </nav>
  );
}

export default BackNav;

