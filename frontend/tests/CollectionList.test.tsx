import { expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import CollectionList from '../src/components/collection/CollectionList';
import { createMockCollection } from './testUtils/factories';

it('renders collection artwork and descriptions and supports keyboard selection', async () => {
  const illustrated = createMockCollection({ name: 'Cameras', heroImageUrl: '/camera.jpg', description: 'Vintage cameras' });
  const plain = createMockCollection({ collectionId: 2, name: 'Books', description: '' });
  const onSelect = vi.fn();
  render(<CollectionList collections={[illustrated, plain]} onSelect={onSelect} />);
  expect(screen.getByRole('img', { name: 'Cameras' })).toHaveAttribute('src', '/camera.jpg');
  expect(screen.getByText('Vintage cameras')).toBeInTheDocument();
  expect(screen.getAllByRole('img')).toHaveLength(1);
  screen.getByRole('button', { name: /Cameras/ }).focus();
  await userEvent.keyboard('{Enter}');
  expect(onSelect).toHaveBeenLastCalledWith(illustrated);
  await userEvent.click(screen.getByRole('button', { name: 'Books' }));
  expect(onSelect).toHaveBeenLastCalledWith(plain);
});
