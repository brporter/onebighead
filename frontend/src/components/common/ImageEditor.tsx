import '../../styles/components/ImageEditor.css';
import { useId, useRef } from 'react';
import { useImagesData } from '../../contexts/useData';
import type { ItemImage } from '../../utils/types';
import { IMAGE_FILE_TYPES, IMAGE_UPLOAD_HINT } from '../../data/images/imageUploadPolicy';
import { useImageUploads } from '../../data/images/useImageUploads';
import { useEditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';

interface ImageEditorProps {
  images: ItemImage[];
  onChange: (update: (current: ItemImage[]) => ItemImage[]) => void;
  onStatusChange?: EditorStatusListener;
}

/** Functional draft updates retain edits made while an upload is in flight. */
function ImageEditor({ images, onChange, onStatusChange }: ImageEditorProps) {
  const { uploadImage } = useImagesData();
  const id = useId();
  const fileInput = useRef<HTMLInputElement>(null);
  const uploads = useImageUploads(uploadImage, added => onChange(current => [...current, ...added]));
  useEditorStatus(false, uploads.pending, onStatusChange);

  return <section className="imageEditor" aria-labelledby={`${id}-title`} aria-busy={uploads.pending}>
    <h3 id={`${id}-title`} className="imageEditor__label">Images</h3>
    <p className="imageEditor__hint" id={`${id}-hint`}>{IMAGE_UPLOAD_HINT}</p>
    {uploads.issues.length > 0 && <div className="imageEditor__error" role="alert">
      <p>Some images could not be added. Successfully uploaded images are kept in your draft.</p>
      <ul>{uploads.issues.map((issue, index) => <li key={index}><strong>{issue.fileName}:</strong> {issue.message}</li>)}</ul>
    </div>}
    {uploads.pending && <p className="imageEditor__status" role="status">Uploading images ({uploads.completed}/{uploads.total})…</p>}
    <div className="imageEditor__grid">
      {images.map((img, index) => <div key={index} className="imageEditor__item">
        <div className="imageEditor__preview">
          <img src={img.url} alt={img.alt} className="imageEditor__image" />
          <button type="button" className="imageEditor__remove" aria-label={`Remove image ${index + 1}`}
            onClick={() => onChange(current => current.filter((_, position) => position !== index))}>×</button>
        </div>
        <label htmlFor={`${id}-description-${index}`} className="imageEditor__caption">Image {index + 1} description</label>
        <input id={`${id}-description-${index}`} type="text" className="imageEditor__input imageEditor__input--alt"
          placeholder="Alt text" value={img.alt}
          onChange={event => {
            const value = event.target.value;
            onChange(current => current.map((image, position) => position === index ? { ...image, alt: value } : image));
          }} />
      </div>)}
    </div>
    <input ref={fileInput} type="file" accept={IMAGE_FILE_TYPES.join(',')} multiple disabled={uploads.pending}
      aria-label="Choose images" aria-describedby={`${id}-hint`} className="imageEditor__fileInput"
      onChange={event => {
        const files = Array.from(event.target.files ?? []);
        event.target.value = '';
        void uploads.select(files);
      }} />
    <button type="button" className="imageEditor__add" onClick={() => fileInput.current!.click()} disabled={uploads.pending}>
      {uploads.pending ? 'Uploading...' : '+ Add Image'}
    </button>
  </section>;
}

export default ImageEditor;
