import React, { useRef, useState } from 'react';
import { useData } from '../../contexts/useData';
import type { ItemImage } from '../../utils/types';

interface ImageEditorProps {
  images: ItemImage[];
  onChange: (images: ItemImage[]) => void;
}

const MAX_FILE_SIZE_MB = 10;
const MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024;
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];

function ImageEditor({ images, onChange }: ImageEditorProps) {
  const { uploadImage } = useData();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  function validateFile(file: File): string | null {
    if (!ALLOWED_TYPES.includes(file.type)) {
      return `${file.name}: Invalid file type. Allowed types: JPEG, PNG, GIF, WebP`;
    }
    if (file.size > MAX_FILE_SIZE_BYTES) {
      return `${file.name}: File size exceeds ${MAX_FILE_SIZE_MB}MB limit`;
    }
    return null;
  }

  function handleAltChange(index: number, value: string) {
    const updated = images.map((img, i) =>
      i === index ? { ...img, alt: value } : img
    );
    onChange(updated);
  }

  async function handleFileSelect(event: React.ChangeEvent<HTMLInputElement>) {
    const files = event.target.files;
    if (!files || files.length === 0) return;

    setUploading(true);
    setUploadError(null);

    // Validate all files first
    const validationErrors: string[] = [];
    const validFiles: File[] = [];

    for (const file of Array.from(files)) {
      const error = validateFile(file);
      if (error) {
        validationErrors.push(error);
      } else {
        validFiles.push(file);
      }
    }

    if (validationErrors.length > 0) {
      setUploadError(validationErrors.join('; '));
      if (validFiles.length === 0) {
        setUploading(false);
        if (fileInputRef.current) {
          fileInputRef.current.value = '';
        }
        return;
      }
    }

    try {
      const newImages: ItemImage[] = [];

      for (const file of validFiles) {
        const result = await uploadImage(file);
        newImages.push({ url: result.url, alt: file.name.replace(/\.[^/.]+$/, '') });
      }

      onChange([...images, ...newImages]);
    } catch (error) {
      setUploadError(error instanceof Error ? error.message : 'Failed to upload image');
    } finally {
      setUploading(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  }

  function handleRemoveImage(index: number) {
    onChange(images.filter((_, i) => i !== index));
  }

  function handleAddClick() {
    fileInputRef.current?.click();
  }

  return (
    <div className="imageEditor">
      <label className="imageEditor__label">Images</label>
      
      {uploadError && (
        <div className="imageEditor__error">{uploadError}</div>
      )}

      <div className="imageEditor__grid">
        {images.map((img, index) => (
          <div key={index} className="imageEditor__item">
            <div className="imageEditor__preview">
              <img src={img.url} alt={img.alt} className="imageEditor__image" />
              <button
                type="button"
                className="imageEditor__remove"
                onClick={() => handleRemoveImage(index)}
                aria-label="Remove image"
              >
                ×
              </button>
            </div>
            <input
              type="text"
              className="imageEditor__input imageEditor__input--alt"
              placeholder="Alt text"
              value={img.alt}
              onChange={(e) => handleAltChange(index, e.target.value)}
            />
          </div>
        ))}
      </div>

      <input
        ref={fileInputRef}
        type="file"
        accept="image/jpeg,image/png,image/gif,image/webp"
        multiple
        className="imageEditor__fileInput"
        onChange={handleFileSelect}
      />
      
      <button
        type="button"
        className="imageEditor__add"
        onClick={handleAddClick}
        disabled={uploading}
      >
        {uploading ? 'Uploading...' : '+ Add Image'}
      </button>
    </div>
  );
}

export default ImageEditor;

