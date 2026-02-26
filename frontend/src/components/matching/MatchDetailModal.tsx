import { useRef, useEffect, useCallback } from 'react';
import { matchesApi, MatchStatus, type MatchResponse } from '../../api';
import MatchMessageThread from './MatchMessageThread';

interface MatchDetailModalProps {
  match: MatchResponse | null;
  isOpen: boolean;
  onClose: () => void;
  onStatusChanged: () => void;
}

function MatchDetailModal({ match, isOpen, onClose, onStatusChanged }: MatchDetailModalProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (isOpen) {
      dialog?.showModal();
    } else {
      dialog?.close();
    }
  }, [isOpen]);

  useEffect(() => {
    const dialog = dialogRef.current;
    const handleClose = () => onClose();
    dialog?.addEventListener('close', handleClose);
    return () => dialog?.removeEventListener('close', handleClose);
  }, [onClose]);

  const handleBackdropClick = (e: React.MouseEvent) => {
    if (e.target === dialogRef.current) onClose();
  };

  const handleUpdateStatus = useCallback(async (status: MatchStatus) => {
    if (!match) return;
    try {
      await matchesApi.updateStatus(match.id, { status });
      onStatusChanged();
    } catch {
      // Error handled silently
    }
  }, [match, onStatusChanged]);

  if (!match) return null;

  const confidencePercent = Math.round(match.confidenceScore * 100);

  return (
    <dialog ref={dialogRef} className="modal-dialog" onClick={handleBackdropClick}>
      <div className="modal match-detail">
        <div className="modal__header">
          <h2>Match Details</h2>
          <button className="modal__close" onClick={onClose} aria-label="Close">&times;</button>
        </div>
        <div className="modal__body">
          <div className="match-detail__confidence">
            <span className={`match-card__confidence ${confidencePercent >= 80 ? 'match-card__confidence--high' : confidencePercent >= 60 ? 'match-card__confidence--medium' : 'match-card__confidence--low'}`}>
              {confidencePercent}% match
            </span>
          </div>
          <div className="match-detail__reason">{match.matchReason}</div>

          <div className="match-detail__items">
            <div className="match-detail__side">
              <h3>Wanted</h3>
              {match.wantItem.primaryImageUrl && (
                <img
                  src={match.wantItem.primaryImageUrl}
                  alt={match.wantItem.name}
                  className="match-detail__image"
                />
              )}
              <div className="match-detail__item-name">{match.wantItem.name}</div>
              {match.wantItem.summary && (
                <div className="match-detail__item-summary">{match.wantItem.summary}</div>
              )}
              <div className="match-detail__workspace">{match.wantItem.workspaceName}</div>
            </div>

            <div className="match-detail__side">
              <h3>For Trade/Sale</h3>
              {match.tradeItem.primaryImageUrl && (
                <img
                  src={match.tradeItem.primaryImageUrl}
                  alt={match.tradeItem.name}
                  className="match-detail__image"
                />
              )}
              <div className="match-detail__item-name">{match.tradeItem.name}</div>
              {match.tradeItem.summary && (
                <div className="match-detail__item-summary">{match.tradeItem.summary}</div>
              )}
              <div className="match-detail__workspace">{match.tradeItem.workspaceName}</div>
            </div>
          </div>

          <div className="match-detail__actions">
            {match.myStatus !== MatchStatus.Saved && (
              <button
                className="btn btn--primary"
                onClick={() => handleUpdateStatus(MatchStatus.Saved)}
              >
                Save Match
              </button>
            )}
            {match.myStatus !== MatchStatus.Dismissed && (
              <button
                className="btn btn--secondary"
                onClick={() => handleUpdateStatus(MatchStatus.Dismissed)}
              >
                Dismiss
              </button>
            )}
          </div>

          <div className="match-detail__messages">
            <h3>Messages</h3>
            <MatchMessageThread matchId={match.id} />
          </div>
        </div>
      </div>
    </dialog>
  );
}

export default MatchDetailModal;
