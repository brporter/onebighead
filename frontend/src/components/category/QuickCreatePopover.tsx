import React, { useState, useEffect, useRef } from 'react';

const RESERVED_NAMES = ['unassigned items'];

interface QuickCreatePopoverProps {
  isVisible: boolean;
  onSave: (name: string) => void;
  onMoreDetails: (name: string) => void;
  onCancel: () => void;
}

function QuickCreatePopover({ isVisible, onSave, onMoreDetails, onCancel }: QuickCreatePopoverProps) {
  const [name, setName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Reset and focus when popover opens
  useEffect(() => {
    if (isVisible) {
      setName('');
      setError(null);
      // Focus after render
      requestAnimationFrame(() => {
        inputRef.current?.focus();
      });
    }
  }, [isVisible]);

  if (!isVisible) return null;

  const validateAndSave = () => {
    const trimmed = name.trim();
    if (!trimmed) {
      setError('Name is required');
      return;
    }
    if (RESERVED_NAMES.includes(trimmed.toLowerCase())) {
      setError(`"${trimmed}" is a reserved name and cannot be used`);
      return;
    }
    onSave(trimmed);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      validateAndSave();
    } else if (e.key === 'Escape') {
      e.preventDefault();
      onCancel();
    }
  };

  return (
    <div className="quickCreatePopover">
      <input
        ref={inputRef}
        type="text"
        className="quickCreatePopover__input modal__input"
        placeholder="Category name"
        value={name}
        onChange={(e) => {
          setName(e.target.value);
          setError(null);
        }}
        onKeyDown={handleKeyDown}
      />
      {error && (
        <div className="quickCreatePopover__error modal__error" role="alert">
          {error}
        </div>
      )}
      <div className="quickCreatePopover__actions">
        <button
          type="button"
          className="modal__button modal__button--secondary"
          onClick={() => onMoreDetails(name)}
        >
          More Details...
        </button>
        <button
          type="button"
          className="modal__button modal__button--secondary"
          onClick={onCancel}
        >
          Cancel
        </button>
        <button
          type="button"
          className="modal__button modal__button--primary"
          onClick={validateAndSave}
        >
          Save
        </button>
      </div>
    </div>
  );
}

export default QuickCreatePopover;
