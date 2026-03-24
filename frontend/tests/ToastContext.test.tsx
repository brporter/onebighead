import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ToastProvider } from '../src/contexts/ToastContext';
import { useToast } from '../src/contexts/useToast';
import { ToastContainer } from '../src/components/common/ToastContainer';

// Test component that exposes toast actions via buttons
function TestHarness({ message = 'Test toast', details }: { message?: string; details?: string }) {
  const { showToast, toasts, dismissToast } = useToast();
  return (
    <div>
      <button onClick={() => showToast(message, details)}>Show Toast</button>
      <span data-testid="toast-count">{toasts.length}</span>
      {toasts.map(t => (
        <button key={t.id} data-testid={`dismiss-${t.id}`} onClick={() => dismissToast(t.id)}>
          Dismiss {t.id}
        </button>
      ))}
    </div>
  );
}

describe('ToastContext and ToastContainer', () => {
  describe('showing toasts', () => {
    it('should show a toast message after showToast is called', async () => {
      const user = userEvent.setup();
      render(
        <ToastProvider autoDismissMs={0}>
          <TestHarness message="Item published." />
          <ToastContainer />
        </ToastProvider>
      );

      await user.click(screen.getByText('Show Toast'));

      expect(screen.getByText('Item published.')).toBeInTheDocument();
    });

    it('should show toast details when provided', async () => {
      const user = userEvent.setup();
      render(
        <ToastProvider autoDismissMs={0}>
          <TestHarness message="Item published." details="Category 'Watches' is now visible." />
          <ToastContainer />
        </ToastProvider>
      );

      await user.click(screen.getByText('Show Toast'));

      expect(screen.getByText('Item published.')).toBeInTheDocument();
      expect(screen.getByText("Category 'Watches' is now visible.")).toBeInTheDocument();
    });

    it('should support multiple simultaneous toasts', async () => {
      function MultiTrigger() {
        const { showToast } = useToast();
        return (
          <>
            <button onClick={() => showToast('First toast')}>First</button>
            <button onClick={() => showToast('Second toast')}>Second</button>
          </>
        );
      }

      const user = userEvent.setup();
      render(
        <ToastProvider autoDismissMs={0}>
          <MultiTrigger />
          <ToastContainer />
        </ToastProvider>
      );

      await user.click(screen.getByText('First'));
      await user.click(screen.getByText('Second'));

      expect(screen.getByText('First toast')).toBeInTheDocument();
      expect(screen.getByText('Second toast')).toBeInTheDocument();
    });
  });

  describe('auto-dismiss', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('should auto-dismiss toast after specified duration', async () => {
      // Capture showToast via a button click to avoid reassignment during render
      function CaptureAndShow({ message }: { message: string }) {
        const { showToast } = useToast();
        return <button onClick={() => showToast(message)}>Trigger</button>;
      }

      render(
        <ToastProvider autoDismissMs={4000}>
          <CaptureAndShow message="Will disappear" />
          <ToastContainer />
        </ToastProvider>
      );

      act(() => {
        screen.getByText('Trigger').click();
      });

      expect(screen.getByText('Will disappear')).toBeInTheDocument();

      act(() => {
        vi.advanceTimersByTime(4000);
      });

      expect(screen.queryByText('Will disappear')).not.toBeInTheDocument();
    });
  });

  describe('dismissing toasts', () => {
    it('should dismiss toast when dismiss button clicked', async () => {
      const user = userEvent.setup();
      render(
        <ToastProvider autoDismissMs={0}>
          <TestHarness message="Dismissable toast" />
          <ToastContainer />
        </ToastProvider>
      );

      await user.click(screen.getByText('Show Toast'));
      expect(screen.getByText('Dismissable toast')).toBeInTheDocument();

      await user.click(screen.getByLabelText('Dismiss'));

      expect(screen.queryByText('Dismissable toast')).not.toBeInTheDocument();
    });

    it('should dismiss specific toast by id via context', async () => {
      const user = userEvent.setup();
      render(
        <ToastProvider autoDismissMs={0}>
          <TestHarness message="Toast to dismiss" />
          <ToastContainer />
        </ToastProvider>
      );

      await user.click(screen.getByText('Show Toast'));
      expect(screen.getByText('Toast to dismiss')).toBeInTheDocument();

      // Click the dismiss button rendered by TestHarness
      const dismissBtn = screen.getByTestId(/dismiss-/);
      await user.click(dismissBtn);

      expect(screen.queryByText('Toast to dismiss')).not.toBeInTheDocument();
    });
  });

  describe('rendering', () => {
    it('should not render container when no toasts are shown', () => {
      render(
        <ToastProvider>
          <ToastContainer />
        </ToastProvider>
      );

      expect(screen.queryByRole('status')).not.toBeInTheDocument();
    });

    it('should render toasts with aria-live polite for accessibility', async () => {
      const user = userEvent.setup();
      render(
        <ToastProvider autoDismissMs={0}>
          <TestHarness message="Accessible toast" />
          <ToastContainer />
        </ToastProvider>
      );

      await user.click(screen.getByText('Show Toast'));

      const container = screen.getByText('Accessible toast').closest('[aria-live]');
      expect(container).toHaveAttribute('aria-live', 'polite');
    });

    it('should render toast with role=status', async () => {
      const user = userEvent.setup();
      render(
        <ToastProvider autoDismissMs={0}>
          <TestHarness message="Status toast" />
          <ToastContainer />
        </ToastProvider>
      );

      await user.click(screen.getByText('Show Toast'));

      expect(screen.getByRole('status')).toBeInTheDocument();
    });
  });
});
