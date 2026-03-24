import { useContext } from 'react';
import ToastContext from './ToastContext';
import type { ToastContextValue } from './ToastContext';

export function useToast(): ToastContextValue {
  return useContext(ToastContext);
}
