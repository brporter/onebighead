import { useRef, useState } from 'react';
import { useData } from './DataContext';
import type { ItemImage } from './types';

interface ImageEditorProps {
  images: ItemImage[];
  onChange: (images: ItemImage[]) => void;
}

function ImageEditor({ images, onChange }: ImageEditorProps) {
  const { uploadImage } = useData();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

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

    try {
      const newImages: ItemImage[] = [];
      
      for (const file of Array.from(files)) {
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

