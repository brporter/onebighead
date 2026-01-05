import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect } from 'vitest';
import Privacy from '../../src/pages/Privacy';

const renderWithRouter = (component: React.ReactElement) => {
  return render(
    <MemoryRouter>
      {component}
    </MemoryRouter>
  );
};

describe('Privacy', () => {
  it('renders the main heading', () => {
    renderWithRouter(<Privacy />);
    expect(screen.getByRole('heading', { name: /Privacy Policy/i })).toBeInTheDocument();
  });

  it('renders the last updated date', () => {
    renderWithRouter(<Privacy />);
    expect(screen.getByText(/Last updated: January 1, 2026/i)).toBeInTheDocument();
  });

  it('renders Introduction section', () => {
    renderWithRouter(<Privacy />);
    expect(screen.getByRole('heading', { name: /Introduction/i })).toBeInTheDocument();
  });

  it('renders Information We Collect section', () => {
    renderWithRouter(<Privacy />);
    expect(screen.getByRole('heading', { name: /Information We Collect/i })).toBeInTheDocument();
  });

  it('renders Personal Information subsection', () => {
    renderWithRouter(<Privacy />);
    expect(screen.getByRole('heading', { name: /Personal Information/i })).toBeInTheDocument();
  });

  it('renders Collection Data subsection', () => {
    renderWithRouter(<Privacy />);
    expect(screen.getByRole('heading', { name: /Collection Data/i })).toBeInTheDocument();
  });

  it('renders Usage Data subsection', () => {
    renderWithRouter(<Privacy />);
    expect(screen.getByRole('heading', { name: /Usage Data/i })).toBeInTheDocument();
  });

  it('renders How We Use Your Information section', () => {
    renderWithRouter(<Privacy />);
    expect(screen.getByRole('heading', { name: /How We Use Your Information/i })).toBeInTheDocument();
  });

  it('renders Data Security section', () => {
    renderWithRouter(<Privacy />);
    expect(screen.getByRole('heading', { name: /Data Security/i })).toBeInTheDocument();
  });

  it('renders Data Retention section', () => {
    renderWithRouter(<Privacy />);
    expect(screen.getByRole('heading', { name: /Data Retention/i })).toBeInTheDocument();
  });

  it('renders Your Rights section', () => {
    renderWithRouter(<Privacy />);
    expect(screen.getByRole('heading', { name: /Your Rights/i })).toBeInTheDocument();
  });

  it('renders Third-Party Services section', () => {
    renderWithRouter(<Privacy />);
    expect(screen.getByRole('heading', { name: /Third-Party Services/i })).toBeInTheDocument();
  });

  it('renders Changes to This Policy section', () => {
    renderWithRouter(<Privacy />);
    expect(screen.getByRole('heading', { name: /Changes to This Policy/i })).toBeInTheDocument();
  });

  it('renders Contact Us section', () => {
    renderWithRouter(<Privacy />);
    expect(screen.getByRole('heading', { name: /Contact Us/i })).toBeInTheDocument();
  });

  it('renders privacy email link', () => {
    renderWithRouter(<Privacy />);
    expect(screen.getByRole('link', { name: /privacy@onebighead.com/i })).toHaveAttribute('href', 'mailto:privacy@onebighead.com');
  });

  it('renders navigation links', () => {
    renderWithRouter(<Privacy />);
    const aboutLinks = screen.getAllByRole('link', { name: /About/i });
    expect(aboutLinks.length).toBeGreaterThan(0);
  });

  it('highlights Privacy Policy link as active', () => {
    renderWithRouter(<Privacy />);
    const privacyLinks = screen.getAllByRole('link', { name: /Privacy Policy/i });
    const headerPrivacyLink = privacyLinks[0];
    expect(headerPrivacyLink).toHaveClass('landing__nav-link--active');
  });

  it('renders footer', () => {
    renderWithRouter(<Privacy />);
    expect(screen.getByText(/© 2026 OneBigHead/i)).toBeInTheDocument();
  });
});

