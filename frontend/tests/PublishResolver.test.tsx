import { StrictMode } from 'react';
import { describe, it, expect } from 'vitest';
import { act, render, screen, waitFor, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { PublishResolver } from '../src/components/common/PublishResolver';
import type { ExecuteResponse, PublishRequirement } from '../src/utils/types';
import { publicationOptions, requirements, saved } from './testUtils/publication';
import { deferred } from './testUtils/deferred';

describe('publication dialog', () => {
  it('shows checking immediately and cancels without waiting for a server response', async () => {
    const options = publicationOptions();
    options.gateway.preflight.mockReturnValue(new Promise(() => {}));
    render(<PublishResolver {...options} />);
    expect(screen.getByRole('dialog', { name: 'Publish' })).toHaveAttribute('open');
    expect(screen.getByRole('status')).toHaveTextContent('Checking visibility');
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(options.dismiss).toHaveBeenCalledTimes(1);
  });

  it('reviews every requirement with unique labels and validates the gallery URL', async () => {
    const options = publicationOptions();
    options.gateway.preflight.mockResolvedValue({ ready: false, requirements });
    render(<PublishResolver {...options} />);
    const input = await screen.findByLabelText('Gallery URL');
    const publish = screen.getByRole('button', { name: 'Publish' });
    expect(input).toHaveAccessibleDescription(/3–50 lowercase/);
    expect(input).toHaveAttribute('aria-invalid', 'false');
    const user = userEvent.setup();
    await user.type(input, 'No');
    expect(input).toHaveAttribute('aria-invalid', 'true');
    await user.clear(input); await user.type(input, 'library');
    for (const checkbox of screen.getAllByRole('checkbox')) await user.click(checkbox);
    expect(screen.getByText(/hide 1 item and 1 category/)).toBeVisible();
    expect(publish).toBeEnabled();
    await user.click(publish);
    await waitFor(() => expect(options.complete).toHaveBeenCalledWith(saved));
    expect(screen.getByRole('status')).toHaveTextContent('Visibility updated.');
  });

  it.each([0, 2])('describes plural items and %s descendant categories when making a collection private', async count => {
    const options = publicationOptions();
    options.request = { ...options.request, action: 'unpublish' };
    options.gateway.preflight.mockResolvedValue({ ready: false, requirements: [{ kind: 'unpublish-will-hide-children', entityType: 'collection', entityId: 2,
      entityName: 'Books', affectedPublicItems: 4, affectedPublicCategories: count }] });
    render(<PublishResolver {...options} />);
    expect(await screen.findByText(/hide 4 items/)).toHaveTextContent(count ? 'and 2 categories' : '4 items from');
    await userEvent.click(screen.getByRole('checkbox', { name: /impact on/ }));
    await userEvent.click(screen.getByRole('button', { name: 'Make private' }));
    await waitFor(() => expect(options.complete).toHaveBeenCalled());
  });

  it('fails closed with a visible explanation for an unsupported requirement', async () => {
    const options = publicationOptions();
    options.gateway.preflight.mockResolvedValue({ ready: false, requirements: [{ kind: 'future' } as unknown as PublishRequirement] });
    render(<PublishResolver {...options} />);
    expect(await screen.findByRole('alert')).toHaveTextContent('not supported');
    expect(screen.getByRole('button', { name: 'Publish' })).toBeDisabled();
    fireEvent(screen.getByRole('dialog'), new Event('cancel', { bubbles: true, cancelable: true }));
    expect(options.dismiss).toHaveBeenCalledTimes(1);
  });

  it('keeps automatic write errors visible and offers a fresh check', async () => {
    const options = publicationOptions();
    options.gateway.preflight.mockResolvedValueOnce({ ready: true, requirements: [] });
    options.gateway.execute.mockRejectedValueOnce(new Error('Offline'));
    render(<StrictMode><PublishResolver {...options} /></StrictMode>);
    expect(await screen.findByRole('alert')).toHaveTextContent('Offline');
    expect(options.gateway.execute).toHaveBeenCalledTimes(1);
    await userEvent.click(screen.getByRole('button', { name: 'Check again' }));
    expect(await screen.findByRole('checkbox', { name: /Books/ })).not.toBeChecked();
    await userEvent.click(screen.getByRole('dialog'));
    expect(options.dismiss).toHaveBeenCalled();
  });

  it('blocks all dismissal paths while saving and retries a failed refresh without writing twice', async () => {
    const options = publicationOptions();
    const write = deferred<ExecuteResponse>();
    options.gateway.execute.mockReturnValue(write.promise);
    options.refresh.mockRejectedValueOnce(new Error('Refresh offline'));
    const view = render(<PublishResolver {...options} />);
    await userEvent.click(await screen.findByRole('checkbox'));
    await userEvent.click(screen.getByRole('button', { name: 'Publish' }));
    const dialog = screen.getByRole('dialog');
    fireEvent(dialog, new Event('cancel', { bubbles: true, cancelable: true })); await userEvent.click(dialog);
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
    expect(screen.getByRole('checkbox')).toBeDisabled();
    expect(options.dismiss).not.toHaveBeenCalled();
    await act(async () => write.resolve(saved));
    expect(await screen.findByRole('dialog', { name: 'Changes saved' })).toHaveTextContent('Your visibility changes were saved');
    await userEvent.click(screen.getByRole('button', { name: 'Retry refresh' }));
    await waitFor(() => expect(options.complete).toHaveBeenCalled());
    expect(options.gateway.execute).toHaveBeenCalledTimes(1);
    view.unmount();
    expect(options.gateway.execute.mock.calls[0][2]!.signal!.aborted).toBe(true);
  });

  it('allows closing after a saved write when refresh remains unavailable', async () => {
    const options = publicationOptions();
    options.gateway.preflight.mockResolvedValue({ ready: true, requirements: [] });
    options.refresh.mockRejectedValue(new Error('Offline'));
    render(<PublishResolver {...options} />);
    await userEvent.click(await screen.findByRole('button', { name: 'Close' }));
    expect(options.dismiss).toHaveBeenCalledTimes(1);
    expect(options.complete).not.toHaveBeenCalled();
  });
});
