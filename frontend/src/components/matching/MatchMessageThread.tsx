import { useState, useEffect, useCallback, useRef } from 'react';
import { matchesApi, type MatchMessageResponse } from '../../api';
import { useAsyncData } from '../../utils/useAsyncData';

interface MatchMessageThreadProps {
  matchId: number;
}

function MatchMessageThread({ matchId }: MatchMessageThreadProps) {
  const [messageText, setMessageText] = useState('');
  const [sending, setSending] = useState(false);
  const [localMessages, setLocalMessages] = useState<MatchMessageResponse[]>([]);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const fetchMessages = useCallback(
    () => matchesApi.getMessages(matchId),
    [matchId],
  );
  const { data: messages, loading } = useAsyncData<MatchMessageResponse[]>(fetchMessages);

  useEffect(() => {
    if (messages) {
      setLocalMessages(messages);
      matchesApi.markMessagesRead(matchId).catch(() => {});
    }
  }, [messages, matchId]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [localMessages]);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = messageText.trim();
    if (!trimmed || sending) return;

    setSending(true);
    try {
      const newMessage = await matchesApi.sendMessage(matchId, { message: trimmed });
      setLocalMessages(prev => [...prev, newMessage]);
      setMessageText('');
    } catch {
      // Error handled silently
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="match-message-thread">
      <div className="match-message-thread__messages">
        {loading && localMessages.length === 0 && (
          <div className="match-message-thread__loading">Loading messages...</div>
        )}
        {localMessages.length === 0 && !loading && (
          <div className="match-message-thread__empty">No messages yet. Start the conversation!</div>
        )}
        {localMessages.map((msg) => (
          <div
            key={msg.id}
            className={`match-message-thread__message ${msg.isMine ? 'match-message-thread__message--mine' : 'match-message-thread__message--theirs'}`}
          >
            <div className="match-message-thread__message-text">{msg.message}</div>
            <div className="match-message-thread__message-time">
              {new Date(msg.createdAt).toLocaleString()}
            </div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>
      <form className="match-message-thread__input" onSubmit={handleSend}>
        <input
          type="text"
          value={messageText}
          onChange={(e) => setMessageText(e.target.value)}
          placeholder="Type a message..."
          maxLength={2000}
          disabled={sending}
        />
        <button type="submit" disabled={sending || !messageText.trim()}>
          {sending ? 'Sending...' : 'Send'}
        </button>
      </form>
    </div>
  );
}

export default MatchMessageThread;
