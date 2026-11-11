import { beforeEach, expect, it, vi } from 'vitest';
import api from '../../src/api/client';
import * as support from '../../src/api/support';
vi.mock('../../src/api/client', () => ({ default: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() } }));
beforeEach(() => vi.clearAllMocks());

it('forwards cancellation to user and administrator reads and preserves filters', async () => {
  const options = { signal: new AbortController().signal };
  await support.getMySupportRequests(options);
  expect(api.get).toHaveBeenLastCalledWith('/support', options);
  await support.getSupportRequest(7, options);
  expect(api.get).toHaveBeenLastCalledWith('/support/7', options);
  await support.getAdminSupportRequest(8, options);
  expect(api.get).toHaveBeenLastCalledWith('/admin/support/8', options);
  await support.getAdminSupportRequests(undefined, options);
  expect(api.get).toHaveBeenLastCalledWith('/admin/support', options);
  await support.getAdminSupportRequests({ status: '', includeDeleted: false, limit: 0, offset: 0 });
  expect(api.get).toHaveBeenLastCalledWith('/admin/support', undefined);
  await support.getAdminSupportRequests({ status: 'InProgress', includeDeleted: true, limit: 20, offset: 40 }, options);
  expect(api.get).toHaveBeenLastCalledWith('/admin/support?status=InProgress&includeDeleted=true&limit=20&offset=40', options);
  await support.getUnreadSupportCount();
  expect(api.get).toHaveBeenLastCalledWith('/support/unread-count', undefined);
  await support.getUnreadSupportCount(options);
  expect(api.get).toHaveBeenLastCalledWith('/support/unread-count', options);
});

it('routes user and administrator commands to the proper endpoints', async () => {
  const request = { subject: 'Help', description: 'Details', email: 'reader@example.com' };
  const reply = { message: 'More details' };
  await support.createSupportRequest(request);
  expect(api.post).toHaveBeenLastCalledWith('/support', request);
  await support.addSupportReply(1, reply);
  expect(api.post).toHaveBeenLastCalledWith('/support/1/reply', reply);
  await support.addAdminSupportReply(2, reply);
  expect(api.post).toHaveBeenLastCalledWith('/admin/support/2/reply', reply);
  await support.markSupportRequestAsRead(1);
  expect(api.post).toHaveBeenLastCalledWith('/support/1/mark-read');
  await support.updateSupportStatus(2, 'Resolved');
  expect(api.put).toHaveBeenLastCalledWith('/admin/support/2/status', { status: 'Resolved' });
  await support.deleteSupportRequest(1);
  expect(api.delete).toHaveBeenLastCalledWith('/support/1');
  await support.adminDeleteSupportRequest(2);
  expect(api.delete).toHaveBeenLastCalledWith('/admin/support/2');
});
