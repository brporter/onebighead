import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { ContentState } from '../src/components/common/ContentState';

describe('ContentState', () => {
  it.each(['loading', 'empty'] as const)('announces %s status', kind => {
    render(<ContentState kind={kind} title="Status message" />);
    expect(screen.getByRole('status')).toHaveTextContent('Status message');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
  it('announces errors with optional guidance and a recovery action', () => {
    render(<ContentState kind="error" title="Unable to load" action={<button>Retry</button>}>Please try again.</ContentState>);
    expect(screen.getByRole('alert')).toHaveTextContent('Unable to load');
    expect(screen.getByText('Please try again.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });
});
