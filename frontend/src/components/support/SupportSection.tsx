import { useState, useEffect } from 'react';
import {
  getMySupportRequests,
  getSupportRequest,
  addSupportReply,
  deleteSupportRequest,
  markSupportRequestAsRead,
  type SupportRequest,
} from '../../api';
import '../../styles/Support.css';

interface SupportSectionProps {
  isFullPage?: boolean;
}

export function SupportSection({ isFullPage = false }: SupportSectionProps) {
  const [requests, setRequests] = useState<SupportRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedRequest, setSelectedRequest] = useState<SupportRequest | null>(null);
  const [replyText, setReplyText] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    loadRequests();
  }, []);

  const loadRequests = async () => {
    try {
      setLoading(true);
      const data = await getMySupportRequests();
      setRequests(data);
    } catch {
      setError('Failed to load support requests');
    } finally {
      setLoading(false);
    }
  };

  const handleSelectRequest = async (request: SupportRequest) => {
    try {
      // Fetch full request with replies
      const fullRequest = await getSupportRequest(request.supportRequestId);
      setSelectedRequest(fullRequest);

      // Mark as read if there are unread replies (use list item's count, not response)
      if (request.unreadCount > 0) {
        await markSupportRequestAsRead(request.supportRequestId);
        // Update local state
        setRequests((prev) =>
          prev.map((r) =>
            r.supportRequestId === request.supportRequestId
              ? { ...r, unreadCount: 0 }
              : r
          )
        );
      }
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
      const newReply = await addSupportReply(selectedRequest.supportRequestId, {
        message: replyText.trim(),
      });

      // Backend reopens Resolved/Closed requests when user replies
      setSelectedRequest((prev) => {
        if (!prev) return null;
        const nextStatus = (prev.status === 'Resolved' || prev.status === 'Closed') ? 'Open' : prev.status;
        return {
          ...prev,
          status: nextStatus,
          replies: [...prev.replies, newReply],
          replyCount: prev.replyCount + 1,
        };
      });

      // Update list
      setRequests((prev) =>
        prev.map((r) => {
          if (r.supportRequestId !== selectedRequest.supportRequestId) {
            return r;
          }
          const nextStatus = (r.status === 'Resolved' || r.status === 'Closed') ? 'Open' : r.status;
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

  const handleDeleteRequest = async (requestId: number) => {
    if (!confirm('Are you sure you want to delete this support request?')) {
      return;
    }

    try {
      await deleteSupportRequest(requestId);
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

  if (loading) {
    return <div className="templateEditor__loading">Loading support requests...</div>;
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
            <span className={getStatusClass(selectedRequest.status)}>
              {selectedRequest.status}
            </span>
            <span>Created {formatDate(selectedRequest.createdAt)}</span>
          </div>
        </div>

        <div className="support-detail__description">{selectedRequest.description}</div>

        {error && <div className="settings__error">{error}</div>}

        {selectedRequest.replies.length > 0 && (
          <div className="support-detail__replies">
            <h4 className="support-detail__replies-title">Replies</h4>
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
                    {reply.isFromAdmin ? 'Support Team' : 'You'}
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
            placeholder="Write a reply..."
            rows={3}
          />
          <div className="support-detail__actions">
            <button
              type="button"
              className="settings__button settings__button--secondary settings__listButton--danger"
              onClick={() => handleDeleteRequest(selectedRequest.supportRequestId)}
            >
              Delete Request
            </button>
            <button
              type="submit"
              className="settings__button settings__button--primary"
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
    <div className="support-requests">
      {error && <div className="settings__error">{error}</div>}

      {requests.length === 0 ? (
        <div className="support-requests__empty">
          You haven't submitted any support requests yet.
        </div>
      ) : (
        requests.map((request) => (
          <div
            key={request.supportRequestId}
            className={`support-request-card ${
              request.unreadCount > 0 ? 'support-request-card--unread' : ''
            }`}
            onClick={() => handleSelectRequest(request)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                handleSelectRequest(request);
              }
            }}
            role="button"
            tabIndex={0}
            aria-label={`Support request: ${request.subject}, ${request.status}, ${request.replyCount} replies${request.unreadCount > 0 ? `, ${request.unreadCount} unread` : ''}`}
          >
            <div className="support-request-card__header">
              <h4 className="support-request-card__subject">{request.subject}</h4>
              <span className={getStatusClass(request.status)}>{request.status}</span>
            </div>
            <p className="support-request-card__preview">{request.description}</p>
            <div className="support-request-card__footer">
              <span>{formatDate(request.createdAt)}</span>
              <span className="support-request-card__replies">
                {request.replyCount} {request.replyCount === 1 ? 'reply' : 'replies'}
                {request.unreadCount > 0 && (
                  <span className="support-badge">{request.unreadCount} new</span>
                )}
              </span>
            </div>
          </div>
        ))
      )}
    </div>
  );
}
