import { expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { DeletionStatsGrid } from '../src/components/common/DeletionStatsGrid';

it('omits the statistics grid when no counts are supplied', () => {
  const { container } = render(<DeletionStatsGrid />);
  expect(container).toBeEmptyDOMElement();
});

it('includes explicit zero counts and omits unspecified statistics', () => {
  render(<DeletionStatsGrid collections={0} items={42} />);
  expect(screen.getByText('Collections').parentElement).toHaveTextContent('0Collections');
  expect(screen.getByText('Items').parentElement).toHaveTextContent('42Items');
  expect(screen.queryByText('Categories')).not.toBeInTheDocument();
  expect(screen.queryByText('Users')).not.toBeInTheDocument();
});
