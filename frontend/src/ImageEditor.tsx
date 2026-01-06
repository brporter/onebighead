import type { ItemImage } from './types';

interface ImageEditorProps {
  images: ItemImage[];
  onChange: (images: ItemImage[]) => void;
}

function ImageEditor({ images, onChange }: ImageEditorProps) {
  function handleImageChange(index: number, field: keyof ItemImage, value: string) {
    const updated = images.map((img, i) =>
      i === index ? { ...img, [field]: value } : img
    );
    onChange(updated);
  }

  function handleAddImage() {
    onChange([...images, { url: '', alt: '' }]);
  }

  function handleRemoveImage(index: number) {
    onChange(images.filter((_, i) => i !== index));
  }

  return (
    <div className="imageEditor">
      <label className="imageEditor__label">Images</label>
      {images.map((img, index) => (
        <div key={index} className="imageEditor__row">
          <input
            type="url"
            className="imageEditor__input imageEditor__input--url"
            placeholder="Image URL"
            value={img.url}
            onChange={(e) => handleImageChange(index, 'url', e.target.value)}
          />
          <input
            type="text"
            className="imageEditor__input imageEditor__input--alt"
            placeholder="Alt text"
            value={img.alt}
            onChange={(e) => handleImageChange(index, 'alt', e.target.value)}
          />
          <button
            type="button"
            className="imageEditor__remove"
            onClick={() => handleRemoveImage(index)}
            aria-label="Remove image"
          >
            ×
          </button>
        </div>
      ))}
      <button
        type="button"
        className="imageEditor__add"
        onClick={handleAddImage}
      >
        + Add Image
      </button>
    </div>
  );
}

export default ImageEditor;

