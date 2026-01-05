import { Link } from 'react-router-dom';
import '../styles/Landing.css';

function Privacy() {
  return (
    <div className="landing">
      <header className="landing__header">
        <div className="landing__header-content">
          <Link to="/" className="landing__logo">OneBigHead</Link>
          <nav className="landing__nav">
            <Link to="/about" className="landing__nav-link">About</Link>
            <Link to="/privacy" className="landing__nav-link landing__nav-link--active">Privacy Policy</Link>
            <Link to="/collections" className="landing__nav-link landing__nav-link--signin">Sign In</Link>
          </nav>
        </div>
      </header>

      <main className="landing__main landing__main--narrow">
        <article className="landing__article">
          <h1>Privacy Policy</h1>
          <p className="landing__date">Last updated: January 1, 2026</p>

          <section>
            <h2>Introduction</h2>
            <p>
              At OneBigHead, we take your privacy seriously. This Privacy Policy explains how we 
              collect, use, disclose, and safeguard your information when you use our collection 
              management service.
            </p>
          </section>

          <section>
            <h2>Information We Collect</h2>
            <h3>Personal Information</h3>
            <p>
              When you create an account, we collect information such as your name, email address, 
              and password. We may also collect billing information if you subscribe to a paid plan.
            </p>
            <h3>Collection Data</h3>
            <p>
              The items, categories, images, and other data you add to your collections are stored 
              on our servers. This data belongs to you and is used solely to provide our service.
            </p>
            <h3>Usage Data</h3>
            <p>
              We automatically collect certain information when you use our service, including your 
              IP address, browser type, operating system, and pages visited. This helps us improve 
              our service and troubleshoot issues.
            </p>
          </section>

          <section>
            <h2>How We Use Your Information</h2>
            <ul>
              <li>To provide and maintain our service</li>
              <li>To notify you about changes to our service</li>
              <li>To provide customer support</li>
              <li>To gather analysis or valuable information to improve our service</li>
              <li>To detect, prevent, and address technical issues</li>
            </ul>
          </section>

          <section>
            <h2>Data Security</h2>
            <p>
              We implement appropriate technical and organizational security measures to protect 
              your personal information. However, no method of transmission over the Internet or 
              electronic storage is 100% secure, and we cannot guarantee absolute security.
            </p>
          </section>

          <section>
            <h2>Data Retention</h2>
            <p>
              We retain your personal information for as long as your account is active or as 
              needed to provide you services. You may request deletion of your account and 
              associated data at any time.
            </p>
          </section>

          <section>
            <h2>Your Rights</h2>
            <p>You have the right to:</p>
            <ul>
              <li>Access the personal information we hold about you</li>
              <li>Request correction of inaccurate data</li>
              <li>Request deletion of your data</li>
              <li>Export your collection data</li>
              <li>Withdraw consent where processing is based on consent</li>
            </ul>
          </section>

          <section>
            <h2>Third-Party Services</h2>
            <p>
              We may use third-party services for analytics, payment processing, and cloud hosting. 
              These services have their own privacy policies governing the use of your information.
            </p>
          </section>

          <section>
            <h2>Changes to This Policy</h2>
            <p>
              We may update this Privacy Policy from time to time. We will notify you of any changes 
              by posting the new Privacy Policy on this page and updating the "Last updated" date.
            </p>
          </section>

          <section>
            <h2>Contact Us</h2>
            <p>
              If you have questions about this Privacy Policy, please contact us at{' '}
              <a href="mailto:privacy@onebighead.com">privacy@onebighead.com</a>.
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

export default Privacy;

