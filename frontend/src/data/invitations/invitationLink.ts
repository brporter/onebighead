import type { InvitationAccess } from './types';

/** Fragments stay out of request URLs; tab-local storage carries the secret through sign-in. */
export function readInvitationLink(id: string, fragment: string, storage: Pick<Storage, 'getItem' | 'setItem'>): InvitationAccess | null {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) return null;
  const key = `workspace-invitation:${id}`;
  const token = fragment ? fragment.slice(1) : storage.getItem(key);
  if (!token || !/^[0-9a-f]{64}$/i.test(token)) return null;
  if (fragment) storage.setItem(key, token);
  return { invitationId: id, token };
}
