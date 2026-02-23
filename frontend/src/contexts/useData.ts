import { useContext } from 'react';
import DataContext from './DataContext';
import type { DataContextValue } from './DataContext';

export function useData(): DataContextValue {
  return useContext(DataContext);
}
