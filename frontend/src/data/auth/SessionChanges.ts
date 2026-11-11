import type { EditorStatus } from '../shared/useEditorStatus';
import { getErrorMessage } from '../../utils/errorUtils';

export type SessionChangeKind = 'workspace' | 'logout' | 'account' | 'account-deletion';
const failureMessages: Record<SessionChangeKind, string> = {
  workspace: 'Unable to switch workspace',
  logout: 'Unable to sign out',
  account: 'Unable to update account',
  'account-deletion': 'Unable to delete account',
};

export interface SessionChangeState {
  kind: SessionChangeKind | null;
  /** Identifies the initiating control without coupling the coordinator to its UI. */
  source?: symbol;
  pending: boolean;
  recovery: boolean;
  leaving: boolean;
  error: string | null;
}

/** Coordinates session writes with editor protection and authoritative read recovery. */
export class SessionChanges {
  private editors = new Map<symbol, EditorStatus>();
  private listeners = new Set<() => void>();
  private state: SessionChangeState = { kind: null, pending: false, recovery: false, leaving: false, error: null };
  private recovery: (() => Promise<boolean>) | null = null;

  getSnapshot = () => this.state;
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };
  protect(status: EditorStatus) {
    const key = Symbol();
    this.editors.set(key, status);
    return () => { this.editors.delete(key); };
  }
  private update(state: Partial<SessionChangeState>) {
    this.state = { ...this.state, ...state };
    this.listeners.forEach(listener => listener());
  }

  async run(kind: SessionChangeKind, change: () => Promise<unknown>, refresh: () => Promise<void>, confirm: () => boolean, source?: symbol): Promise<boolean> {
    if (this.state.pending || this.state.recovery || this.state.leaving) return false;
    const statuses = [...this.editors.values()];
    if (statuses.some(status => status.pending)) {
      this.update({ kind, source, error: 'Wait for the current action to finish before changing your session.' });
      return false;
    }
    if (statuses.some(status => status.dirty) && !confirm()) {
      this.update({ kind, source, error: null });
      return false;
    }
    this.update({ kind, source, pending: true, error: null });
    let changeError: string | null = null;
    try { await change(); } catch (cause) {
      changeError = getErrorMessage(cause, failureMessages[kind]);
    }
    if ((kind === 'logout' || kind === 'account-deletion') && changeError === null) {
      this.update({ pending: false, leaving: true });
      return true;
    }
    // A failed response can still follow a committed session write. Reconcile
    // before re-enabling the old workspace, and never retry that write implicitly.
    this.recovery = async () => {
      this.update({ pending: true });
      try {
        await refresh();
        this.recovery = null;
        this.update({ pending: false, recovery: false, error: changeError });
        return changeError === null;
      } catch (cause) {
        this.update({ pending: false, recovery: true, error: getErrorMessage(cause, 'Unable to refresh your session') });
        return false;
      }
    };
    return this.recovery();
  }

  retryRefresh = async () => {
    if (this.state.pending || !this.recovery) return false;
    return this.recovery();
  };
}
