import { Link } from 'react-router-dom';
import '../styles/Landing.css';

function Landing() {
  return (
    <div className="landing">
      <header className="landing__header">
        <div className="landing__header-content">
          <Link to="/" className="landing__logo">OneBigHead</Link>
          <nav className="landing__nav">
            <Link to="/about" className="landing__nav-link">About</Link>
            <Link to="/privacy" className="landing__nav-link">Privacy Policy</Link>
            <Link to="/collections" className="landing__nav-link landing__nav-link--signin">Sign In</Link>
          </nav>
        </div>
      </header>

      <main className="landing__main">
        <section className="landing__hero">
          <h1 className="landing__title">Welcome to OneBigHead</h1>
          <p className="landing__tagline">
            Your personal collection manager for vintage technology, rare collectibles, and cherished items.
          </p>
          <div className="landing__cta">
            <Link to="/signup" className="landing__button landing__button--primary">Get Started</Link>
            <Link to="/about" className="landing__button landing__button--secondary">Learn More</Link>
          </div>
        </section>

        <section className="landing__features">
          <h2 className="landing__section-title">Why Choose OneBigHead?</h2>
          <div className="landing__features-grid">
            <article className="landing__feature">
              <h3>Organize</h3>
              <p>Categorize your collections with our intuitive hierarchical system. Create nested categories to match your exact organizational needs.</p>
            </article>
            <article className="landing__feature">
              <h3>Document</h3>
              <p>Keep detailed records of each item including descriptions, images, acquisition dates, and custom properties specific to your collection type.</p>
            </article>
            <article className="landing__feature">
              <h3>Discover</h3>
              <p>Browse your collections with powerful filtering and search capabilities. Find exactly what you're looking for in seconds.</p>
            </article>
          </div>
        </section>

        <section className="landing__about-preview">
          <h2 className="landing__section-title">Built for Collectors</h2>
          <p>
            Whether you collect vintage Macintosh computers, rare coins, classic vinyl records, or anything else that sparks your passion, 
            OneBigHead provides the tools you need to manage and showcase your treasures.
          </p>
          <p>
            Our platform is designed by collectors, for collectors. We understand the importance of preserving not just items, 
            but the stories and memories that make each piece special.
          </p>
        </section>
      </main>

      <footer className="landing__footer">
        <div className="landing__footer-content">
          <p>&copy; 2026 OneBigHead. All rights reserved.</p>
          <nav className="landing__footer-nav">
            <Link to="/about">About</Link>
            <Link to="/privacy">Privacy Policy</Link>
            <Link to="/signup">Sign Up</Link>
          </nav>
        </div>
      </footer>
    </div>
  );
}

export default Landing;

