import { useToast } from '../../contexts/useToast';
import '../../styles/components/ToastContainer.css';

export function ToastContainer() {
  const { toasts, dismissToast } = useToast();

  if (toasts.length === 0) return null;

  return (
    <div className="toast-container" aria-live="polite">
      {toasts.map(toast => (
        <div key={toast.id} className="toast" role="status">
          <div className="toast__content">
            <p className="toast__message">{toast.message}</p>
            {toast.details && (
              <p className="toast__details">{toast.details}</p>
            )}
          </div>
          <button
            type="button"
            className="toast__dismiss"
            onClick={() => dismissToast(toast.id)}
            aria-label="Dismiss"
          >
            &times;
          </button>
        </div>
      ))}
    </div>
  );
}
