import { expect, it, vi } from 'vitest';
import { api } from '../../src/api/client';
import { invitationsApi } from '../../src/api/invitations';
import { usersApi } from '../../src/api/users';
import { createdInvitation } from '../testUtils/team';
vi.mock('../../src/api/client', () => ({ api: { get: vi.fn(), post: vi.fn(), delete: vi.fn() } }));

it('sends invitation secrets only in request bodies and forwards preview cancellation', async () => {
  const created = createdInvitation();
  const request = { invitationId: created.invitation.invitationId, token: created.token };
  const options = { signal: new AbortController().signal };
  await invitationsApi.preview(request, options);
  expect(api.post).toHaveBeenLastCalledWith('/invitations/preview', request, options);
  await invitationsApi.preview(request);
  expect(api.post).toHaveBeenLastCalledWith('/invitations/preview', request, undefined);
  await invitationsApi.accept(request);
  expect(api.post).toHaveBeenLastCalledWith('/invitations/accept', request);
  await usersApi.getInvitations(options);
  expect(api.get).toHaveBeenLastCalledWith('/invitations', options);
  await usersApi.getInvitations();
  expect(api.get).toHaveBeenLastCalledWith('/invitations', undefined);
  await usersApi.cancelInvitation('id/with space');
  expect(api.delete).toHaveBeenLastCalledWith('/invitations/id%2Fwith%20space');
});
