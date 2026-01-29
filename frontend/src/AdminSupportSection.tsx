import { useState, useEffect } from 'react';
import {
  getAdminSupportRequests,
  getAdminSupportRequest,
  addAdminSupportReply,
  updateSupportStatus,
  adminDeleteSupportRequest,
  type SupportRequest,
} from './api';
import './styles/Support.css';

export function AdminSupportSection() {
  const [requests, setRequests] = useState<SupportRequest[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedRequest, setSelectedRequest] = useState<SupportRequest | null>(null);
  const [replyText, setReplyText] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [includeDeleted, setIncludeDeleted] = useState(false);
  const [page, setPage] = useState(0);
  const pageSize = 20;

  useEffect(() => {
    loadRequests();
  }, [statusFilter, includeDeleted, page]);

  const loadRequests = async () => {
    try {
      setLoading(true);
      setError(null); // Clear previous errors
      const data = await getAdminSupportRequests({
        status: statusFilter || undefined,
        includeDeleted,
        limit: pageSize,
        offset: page * pageSize,
      });
      setRequests(data.items);
      setTotal(data.total);
    } catch {
      setError('Failed to load support requests');
    } finally {
      setLoading(false);
    }
  };

  const handleSelectRequest = async (request: SupportRequest) => {
    try {
      const fullRequest = await getAdminSupportRequest(request.supportRequestId);
      setSelectedRequest(fullRequest);
    } catch {
      setError('Failed to load request details');
    }
  };

  const handleBackToList = () => {
    setSelectedRequest(null);
    setReplyText('');
    setError(null);
  };

  const handleSubmitReply = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedRequest || !replyText.trim()) return;

    setIsSubmitting(true);
    setError(null);

    try {
      const newReply = await addAdminSupportReply(selectedRequest.supportRequestId, {
        message: replyText.trim(),
      });

      // Backend auto-transitions Open -> InProgress when admin replies
      setSelectedRequest((prev) => {
        if (!prev) return null;
        const nextStatus = prev.status === 'Open' ? 'InProgress' : prev.status;
        return {
          ...prev,
          status: nextStatus,
          replies: [...prev.replies, newReply],
          replyCount: prev.replyCount + 1,
        };
      });

      setRequests((prev) =>
        prev.map((r) => {
          if (r.supportRequestId !== selectedRequest.supportRequestId) {
            return r;
          }
          const nextStatus = r.status === 'Open' ? 'InProgress' : r.status;
          return {
            ...r,
            status: nextStatus,
            replyCount: r.replyCount + 1,
          };
        })
      );

      setReplyText('');
    } catch {
      setError('Failed to send reply');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleStatusChange = async (newStatus: string) => {
    if (!selectedRequest) return;

    try {
      const updated = await updateSupportStatus(selectedRequest.supportRequestId, newStatus);
      // Preserve existing selectedRequest details (e.g., replies) and only update status/updatedAt
      setSelectedRequest((prev) =>
        prev && prev.supportRequestId === selectedRequest.supportRequestId
          ? { ...prev, status: newStatus, updatedAt: updated.updatedAt }
          : prev
      );
      // Update the local list state to reflect the status change
      setRequests((prev) =>
        prev.map((r) =>
          r.supportRequestId === selectedRequest.supportRequestId 
            ? { ...r, status: newStatus, updatedAt: updated.updatedAt } 
            : r
        )
      );
    } catch {
      setError('Failed to update status');
    }
  };

  const handleDeleteRequest = async (requestId: number) => {
    if (!confirm('Are you sure you want to delete this support request?')) {
      return;
    }

    try {
      await adminDeleteSupportRequest(requestId);
      setRequests((prev) => prev.filter((r) => r.supportRequestId !== requestId));
      if (selectedRequest?.supportRequestId === requestId) {
        setSelectedRequest(null);
      }
    } catch {
      setError('Failed to delete request');
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getStatusClass = (status: string) => {
    return `support-request-card__status support-request-card__status--${status.toLowerCase()}`;
  };

  const totalPages = Math.ceil(total / pageSize);

  if (loading && requests.length === 0) {
    return <p className="systemAdmin__loading">Loading support requests...</p>;
  }

  // Detail view
  if (selectedRequest) {
    return (
      <div className="support-detail">
        <button className="support-detail__back" onClick={handleBackToList}>
          ← Back to requests
        </button>

        <div className="support-detail__header">
          <h3 className="support-detail__subject">{selectedRequest.subject}</h3>
          <div className="support-detail__meta">
            <select
              className="systemAdmin__input"
              value={selectedRequest.status}
              onChange={(e) => handleStatusChange(e.target.value)}
              style={{ width: 'auto', padding: '0.25rem 0.5rem' }}
            >
              <option value="Open">Open</option>
              <option value="InProgress">In Progress</option>
              <option value="Resolved">Resolved</option>
              <option value="Closed">Closed</option>
            </select>
            <span>From: {selectedRequest.email}</span>
            <span>Created {formatDate(selectedRequest.createdAt)}</span>
            {selectedRequest.userId && <span>(Registered User)</span>}
          </div>
        </div>

        <div className="support-detail__description">{selectedRequest.description}</div>

        {error && <div className="systemAdmin__error">{error}</div>}

        {selectedRequest.replies.length > 0 && (
          <div className="support-detail__replies">
            <h4 className="support-detail__replies-title">Conversation</h4>
            {selectedRequest.replies.map((reply) => (
              <div
                key={reply.supportReplyId}
                className={`support-reply ${reply.isFromAdmin ? 'support-reply--admin' : ''}`}
              >
                <div className="support-reply__header">
                  <span
                    className={`support-reply__author ${
                      reply.isFromAdmin ? 'support-reply__author--admin' : ''
                    }`}
                  >
                    {reply.isFromAdmin ? 'Admin' : 'User'}
                  </span>
                  <span className="support-reply__date">{formatDate(reply.createdAt)}</span>
                </div>
                <p className="support-reply__message">{reply.message}</p>
              </div>
            ))}
          </div>
        )}

        <form className="support-detail__reply-form" onSubmit={handleSubmitReply}>
          <textarea
            className="support-detail__reply-textarea"
            value={replyText}
            onChange={(e) => setReplyText(e.target.value)}
            placeholder="Write a reply (will send email notification)..."
            rows={3}
          />
          <div className="support-detail__actions">
            <button
              type="button"
              className="systemAdmin__actionButton systemAdmin__actionButton--danger"
              onClick={() => handleDeleteRequest(selectedRequest.supportRequestId)}
            >
              Delete
            </button>
            <button
              type="submit"
              className="systemAdmin__button systemAdmin__button--primary"
              disabled={isSubmitting || !replyText.trim()}
            >
              {isSubmitting ? 'Sending...' : 'Send Reply'}
            </button>
          </div>
        </form>
      </div>
    );
  }

  // List view
  return (
    <div>
      <div className="systemAdmin__filterRow" style={{ display: 'flex', gap: '1rem', marginBottom: '1rem', alignItems: 'center' }}>
        <select
          className="systemAdmin__input"
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            setPage(0);
          }}
          style={{ width: 'auto' }}
        >
          <option value="">All Statuses</option>
          <option value="Open">Open</option>
          <option value="InProgress">In Progress</option>
          <option value="Resolved">Resolved</option>
          <option value="Closed">Closed</option>
        </select>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <input
            type="checkbox"
            checked={includeDeleted}
            onChange={(e) => {
              setIncludeDeleted(e.target.checked);
              setPage(0);
            }}
          />
          Include deleted
        </label>
        <span style={{ marginLeft: 'auto', color: '#666' }}>
          Showing {requests.length} of {total} requests
        </span>
      </div>

      {error && <div className="systemAdmin__error">{error}</div>}

      {requests.length === 0 ? (
        <p className="systemAdmin__emptyMessage">No support requests found.</p>
      ) : (
        <>
          <table className="systemAdmin__table">
            <thead>
              <tr>
                <th>Subject</th>
                <th>From</th>
                <th>Status</th>
                <th>Replies</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {requests.map((request) => (
                <tr
                  key={request.supportRequestId}
                  style={request.isDeleted ? { opacity: 0.5 } : undefined}
                >
                  <td>
                    <button
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--color-primary)',
                        cursor: 'pointer',
                        textAlign: 'left',
                        padding: 0,
                        font: 'inherit',
                      }}
                      onClick={() => handleSelectRequest(request)}
                    >
                      {request.subject}
                    </button>
                    {request.isDeleted && <span style={{ color: '#999', marginLeft: '0.5rem' }}>(deleted)</span>}
                  </td>
                  <td>
                    {request.email}
                    {request.userId && ' (user)'}
                  </td>
                  <td>
                    <span className={getStatusClass(request.status)}>{request.status}</span>
                  </td>
                  <td>{request.replyCount}</td>
                  <td>{formatDate(request.createdAt)}</td>
                  <td>
                    <button
                      className="systemAdmin__actionButton"
                      onClick={() => handleSelectRequest(request)}
                    >
                      View
                    </button>
                    {!request.isDeleted && (
                      <button
                        className="systemAdmin__actionButton systemAdmin__actionButton--danger"
                        onClick={() => handleDeleteRequest(request.supportRequestId)}
                      >
                        Delete
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {totalPages > 1 && (
            <div style={{ display: 'flex', justifyContent: 'center', gap: '0.5rem', marginTop: '1rem' }}>
              <button
                className="systemAdmin__button"
                disabled={page === 0}
                onClick={() => setPage((p) => p - 1)}
              >
                Previous
              </button>
              <span style={{ padding: '0.5rem' }}>
                Page {page + 1} of {totalPages}
              </span>
              <button
                className="systemAdmin__button"
                disabled={page >= totalPages - 1}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
