import { createContext, useState, useCallback, useRef, type ReactNode } from 'react';

export interface ToastMessage {
  id: number;
  message: string;
  details?: string;
}

export interface ToastContextValue {
  toasts: ToastMessage[];
  showToast: (message: string, details?: string) => void;
  dismissToast: (id: number) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

interface ToastProviderProps {
  children: ReactNode;
  autoDismissMs?: number;
}

export function ToastProvider({ children, autoDismissMs = 4000 }: ToastProviderProps) {
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const nextIdRef = useRef(1);

  const dismissToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const showToast = useCallback((message: string, details?: string) => {
    const id = nextIdRef.current++;
    const toast: ToastMessage = { id, message, details };
    setToasts(prev => [...prev, toast]);

    if (autoDismissMs > 0) {
      setTimeout(() => {
        dismissToast(id);
      }, autoDismissMs);
    }
  }, [autoDismissMs, dismissToast]);

  return (
    <ToastContext.Provider value={{ toasts, showToast, dismissToast }}>
      {children}
    </ToastContext.Provider>
  );
}

export default ToastContext;
