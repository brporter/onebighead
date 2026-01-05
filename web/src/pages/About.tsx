import { Link } from 'react-router-dom';
import '../styles/Landing.css';

function About() {
  return (
    <div className="landing">
      <header className="landing__header">
        <div className="landing__header-content">
          <Link to="/" className="landing__logo">OneBigHead</Link>
          <nav className="landing__nav">
            <Link to="/about" className="landing__nav-link landing__nav-link--active">About</Link>
            <Link to="/privacy" className="landing__nav-link">Privacy Policy</Link>
            <Link to="/collections" className="landing__nav-link landing__nav-link--signin">Sign In</Link>
          </nav>
        </div>
      </header>

      <main className="landing__main landing__main--narrow">
        <article className="landing__article">
          <h1>About OneBigHead</h1>
          
          <section>
            <h2>Our Mission</h2>
            <p>
              OneBigHead was created with a simple mission: to help collectors organize, document, 
              and celebrate their collections. We believe that every collection tells a story, and 
              our platform is designed to help you preserve and share those stories.
            </p>
          </section>

          <section>
            <h2>Our Story</h2>
            <p>
              Founded by passionate collectors of vintage technology, OneBigHead grew out of a 
              personal need for better collection management tools. What started as a simple 
              spreadsheet to track vintage Macintosh computers evolved into a comprehensive 
              platform for all types of collections.
            </p>
            <p>
              We understand the joy of finding that rare piece, the satisfaction of completing 
              a series, and the importance of preserving the history behind each item. That's 
              why we've built OneBigHead with collectors in mind.
            </p>
          </section>

          <section>
            <h2>What We Offer</h2>
            <ul>
              <li>Flexible categorization system with unlimited nesting</li>
              <li>Custom property definitions for different collection types</li>
              <li>Image galleries for each item</li>
              <li>Search and filtering capabilities</li>
              <li>Secure, private storage of your collection data</li>
              <li>Export options for backup and sharing</li>
            </ul>
          </section>

          <section>
            <h2>Contact Us</h2>
            <p>
              Have questions, feedback, or suggestions? We'd love to hear from you. 
              Reach out to us at <a href="mailto:hello@onebighead.com">hello@onebighead.com</a>.
            </p>
          </section>
        </article>
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

export default About;

