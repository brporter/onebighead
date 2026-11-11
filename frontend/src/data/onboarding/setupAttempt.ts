export interface SetupDraft {
  workspaceName: string;
  collectionName: string;
  description: string;
  themeId: number;
}

export interface SetupAttempt {
  requestId: string;
  draft: SetupDraft;
}

/** Persistence is supplied by the host; a failed write must prevent the API command. */
export interface SetupAttemptStore {
  read(): SetupAttempt | undefined;
  save(attempt: SetupAttempt): void;
  clear(requestId: string): void;
}
