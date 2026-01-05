import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect, vi } from 'vitest';
import userEvent from '@testing-library/user-event';
import SignUp from '../../src/pages/SignUp';

const renderWithRouter = (component: React.ReactElement) => {
  return render(
    <MemoryRouter>
      {component}
    </MemoryRouter>
  );
};

describe('SignUp', () => {
  it('renders the main heading', () => {
    renderWithRouter(<SignUp />);
    expect(screen.getByRole('heading', { name: /Create Your Account/i })).toBeInTheDocument();
  });

  it('renders the subtitle', () => {
    renderWithRouter(<SignUp />);
    expect(screen.getByText(/Start organizing your collections today/i)).toBeInTheDocument();
  });

  it('renders Full Name input', () => {
    renderWithRouter(<SignUp />);
    expect(screen.getByLabelText(/Full Name/i)).toBeInTheDocument();
  });

  it('renders Email input', () => {
    renderWithRouter(<SignUp />);
    expect(screen.getByLabelText(/Email Address/i)).toBeInTheDocument();
  });

  it('renders Password input', () => {
    renderWithRouter(<SignUp />);
    expect(screen.getByLabelText(/^Password$/i)).toBeInTheDocument();
  });

  it('renders Confirm Password input', () => {
    renderWithRouter(<SignUp />);
    expect(screen.getByLabelText(/Confirm Password/i)).toBeInTheDocument();
  });

  it('renders terms checkbox', () => {
    renderWithRouter(<SignUp />);
    expect(screen.getByRole('checkbox')).toBeInTheDocument();
    expect(screen.getByText(/I agree to the/i)).toBeInTheDocument();
  });

  it('renders Create Account button', () => {
    renderWithRouter(<SignUp />);
    expect(screen.getByRole('button', { name: /Create Account/i })).toBeInTheDocument();
  });

  it('renders sign in link for existing users', () => {
    renderWithRouter(<SignUp />);
    expect(screen.getByText(/Already have an account\?/i)).toBeInTheDocument();
    const signInLinks = screen.getAllByRole('link', { name: /Sign in/i });
    expect(signInLinks.some(link => link.getAttribute('href') === '/collections')).toBe(true);
  });

  it('allows typing in name input', async () => {
    const user = userEvent.setup();
    renderWithRouter(<SignUp />);
    
    const nameInput = screen.getByLabelText(/Full Name/i);
    await user.type(nameInput, 'John Doe');
    
    expect(nameInput).toHaveValue('John Doe');
  });

  it('allows typing in email input', async () => {
    const user = userEvent.setup();
    renderWithRouter(<SignUp />);
    
    const emailInput = screen.getByLabelText(/Email Address/i);
    await user.type(emailInput, 'john@example.com');
    
    expect(emailInput).toHaveValue('john@example.com');
  });

  it('allows typing in password input', async () => {
    const user = userEvent.setup();
    renderWithRouter(<SignUp />);
    
    const passwordInput = screen.getByLabelText(/^Password$/i);
    await user.type(passwordInput, 'secretpassword');
    
    expect(passwordInput).toHaveValue('secretpassword');
  });

  it('allows typing in confirm password input', async () => {
    const user = userEvent.setup();
    renderWithRouter(<SignUp />);
    
    const confirmPasswordInput = screen.getByLabelText(/Confirm Password/i);
    await user.type(confirmPasswordInput, 'secretpassword');
    
    expect(confirmPasswordInput).toHaveValue('secretpassword');
  });

  it('handles form submission', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const user = userEvent.setup();
    renderWithRouter(<SignUp />);
    
    await user.type(screen.getByLabelText(/Full Name/i), 'John Doe');
    await user.type(screen.getByLabelText(/Email Address/i), 'john@example.com');
    await user.type(screen.getByLabelText(/^Password$/i), 'secretpassword');
    await user.type(screen.getByLabelText(/Confirm Password/i), 'secretpassword');
    await user.click(screen.getByRole('checkbox'));
    await user.click(screen.getByRole('button', { name: /Create Account/i }));
    
    expect(consoleSpy).toHaveBeenCalledWith('Sign up submitted:', { name: 'John Doe', email: 'john@example.com' });
    
    consoleSpy.mockRestore();
  });

  it('renders navigation links', () => {
    renderWithRouter(<SignUp />);
    const aboutLinks = screen.getAllByRole('link', { name: /About/i });
    expect(aboutLinks.length).toBeGreaterThan(0);
    expect(aboutLinks[0]).toHaveAttribute('href', '/about');
    const privacyLinks = screen.getAllByRole('link', { name: /Privacy Policy/i });
    expect(privacyLinks.length).toBeGreaterThan(0);
    expect(privacyLinks[0]).toHaveAttribute('href', '/privacy');
  });

  it('renders footer', () => {
    renderWithRouter(<SignUp />);
    expect(screen.getByText(/© 2026 OneBigHead/i)).toBeInTheDocument();
  });

  it('has required attributes on form fields', () => {
    renderWithRouter(<SignUp />);
    
    expect(screen.getByLabelText(/Full Name/i)).toBeRequired();
    expect(screen.getByLabelText(/Email Address/i)).toBeRequired();
    expect(screen.getByLabelText(/^Password$/i)).toBeRequired();
    expect(screen.getByLabelText(/Confirm Password/i)).toBeRequired();
    expect(screen.getByRole('checkbox')).toBeRequired();
  });

  it('has password inputs with minLength', () => {
    renderWithRouter(<SignUp />);
    
    expect(screen.getByLabelText(/^Password$/i)).toHaveAttribute('minLength', '8');
    expect(screen.getByLabelText(/Confirm Password/i)).toHaveAttribute('minLength', '8');
  });
});

