import { useState } from 'react';
import { Link } from 'react-router-dom';
import '../styles/Landing.css';

function SignUp() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [name, setName] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Sign up logic would go here
    console.log('Sign up submitted:', { name, email });
  };

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

      <main className="landing__main landing__main--centered">
        <div className="landing__form-container">
          <h1>Create Your Account</h1>
          <p className="landing__form-subtitle">
            Start organizing your collections today.
          </p>

          <form className="landing__form" onSubmit={handleSubmit}>
            <div className="landing__form-group">
              <label htmlFor="name">Full Name</label>
              <input
                type="text"
                id="name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Enter your name"
                required
              />
            </div>

            <div className="landing__form-group">
              <label htmlFor="email">Email Address</label>
              <input
                type="email"
                id="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter your email"
                required
              />
            </div>

            <div className="landing__form-group">
              <label htmlFor="password">Password</label>
              <input
                type="password"
                id="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Create a password"
                required
                minLength={8}
              />
            </div>

            <div className="landing__form-group">
              <label htmlFor="confirmPassword">Confirm Password</label>
              <input
                type="password"
                id="confirmPassword"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm your password"
                required
                minLength={8}
              />
            </div>

            <div className="landing__form-group landing__form-group--checkbox">
              <input type="checkbox" id="terms" required />
              <label htmlFor="terms">
                I agree to the <Link to="/privacy">Privacy Policy</Link>
              </label>
            </div>

            <button type="submit" className="landing__button landing__button--primary landing__button--full">
              Create Account
            </button>
          </form>

          <p className="landing__form-footer">
            Already have an account? <Link to="/collections">Sign in</Link>
          </p>
        </div>
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

export default SignUp;

