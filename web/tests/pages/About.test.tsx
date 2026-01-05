import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect } from 'vitest';
import About from '../../src/pages/About';

const renderWithRouter = (component: React.ReactElement) => {
  return render(
    <MemoryRouter>
      {component}
    </MemoryRouter>
  );
};

describe('About', () => {
  it('renders the main heading', () => {
    renderWithRouter(<About />);
    expect(screen.getByRole('heading', { name: /About OneBigHead/i })).toBeInTheDocument();
  });

  it('renders Our Mission section', () => {
    renderWithRouter(<About />);
    expect(screen.getByRole('heading', { name: /Our Mission/i })).toBeInTheDocument();
  });

  it('renders Our Story section', () => {
    renderWithRouter(<About />);
    expect(screen.getByRole('heading', { name: /Our Story/i })).toBeInTheDocument();
  });

  it('renders What We Offer section', () => {
    renderWithRouter(<About />);
    expect(screen.getByRole('heading', { name: /What We Offer/i })).toBeInTheDocument();
  });

  it('renders Contact Us section', () => {
    renderWithRouter(<About />);
    expect(screen.getByRole('heading', { name: /Contact Us/i })).toBeInTheDocument();
  });

  it('renders contact email link', () => {
    renderWithRouter(<About />);
    expect(screen.getByRole('link', { name: /hello@onebighead.com/i })).toHaveAttribute('href', 'mailto:hello@onebighead.com');
  });

  it('renders navigation links', () => {
    renderWithRouter(<About />);
    const aboutLinks = screen.getAllByRole('link', { name: /About/i });
    expect(aboutLinks.length).toBeGreaterThan(0);
    const privacyLinks = screen.getAllByRole('link', { name: /Privacy Policy/i });
    expect(privacyLinks.length).toBeGreaterThan(0);
  });

  it('renders Sign In link', () => {
    renderWithRouter(<About />);
    const signInLinks = screen.getAllByRole('link', { name: /Sign In/i });
    expect(signInLinks[0]).toHaveAttribute('href', '/collections');
  });

  it('renders footer', () => {
    renderWithRouter(<About />);
    expect(screen.getByText(/© 2026 OneBigHead/i)).toBeInTheDocument();
  });

  it('highlights About link as active', () => {
    renderWithRouter(<About />);
    const navLinks = screen.getAllByRole('link', { name: /About/i });
    const headerAboutLink = navLinks[0];
    expect(headerAboutLink).toHaveClass('landing__nav-link--active');
  });
});

