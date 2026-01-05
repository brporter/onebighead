import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect } from 'vitest';
import Landing from '../../src/pages/Landing';

const renderWithRouter = (component: React.ReactElement) => {
  return render(
    <MemoryRouter>
      {component}
    </MemoryRouter>
  );
};

describe('Landing', () => {
  it('renders the main heading', () => {
    renderWithRouter(<Landing />);
    expect(screen.getByRole('heading', { name: /Welcome to OneBigHead/i })).toBeInTheDocument();
  });

  it('renders the tagline', () => {
    renderWithRouter(<Landing />);
    expect(screen.getByText(/Your personal collection manager/i)).toBeInTheDocument();
  });

  it('renders navigation links', () => {
    renderWithRouter(<Landing />);
    const aboutLinks = screen.getAllByRole('link', { name: /About/i });
    expect(aboutLinks.length).toBeGreaterThan(0);
    expect(aboutLinks[0]).toHaveAttribute('href', '/about');
    const privacyLinks = screen.getAllByRole('link', { name: /Privacy Policy/i });
    expect(privacyLinks.length).toBeGreaterThan(0);
    expect(privacyLinks[0]).toHaveAttribute('href', '/privacy');
  });

  it('renders Sign In link pointing to collections', () => {
    renderWithRouter(<Landing />);
    const signInLinks = screen.getAllByRole('link', { name: /Sign In/i });
    expect(signInLinks[0]).toHaveAttribute('href', '/collections');
  });

  it('renders Get Started button', () => {
    renderWithRouter(<Landing />);
    expect(screen.getByRole('link', { name: /Get Started/i })).toHaveAttribute('href', '/signup');
  });

  it('renders feature sections', () => {
    renderWithRouter(<Landing />);
    expect(screen.getByRole('heading', { name: /Organize/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Document/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Discover/i })).toBeInTheDocument();
  });

  it('renders footer with copyright', () => {
    renderWithRouter(<Landing />);
    expect(screen.getByText(/© 2026 OneBigHead/i)).toBeInTheDocument();
  });

  it('renders logo link pointing to home', () => {
    renderWithRouter(<Landing />);
    const logoLinks = screen.getAllByRole('link', { name: /OneBigHead/i });
    expect(logoLinks[0]).toHaveAttribute('href', '/');
  });

  it('renders the Why Choose section', () => {
    renderWithRouter(<Landing />);
    expect(screen.getByRole('heading', { name: /Why Choose OneBigHead\?/i })).toBeInTheDocument();
  });

  it('renders Built for Collectors section', () => {
    renderWithRouter(<Landing />);
    expect(screen.getByRole('heading', { name: /Built for Collectors/i })).toBeInTheDocument();
  });
});

