import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { cognitoService } from '../../services/cognitoService';
import './AuthForms.css';

interface LoginFormProps {
  onSwitchToRegister: () => void;
  onSwitchToForgotPassword?: () => void;
  successMessage?: string;
}

const LoginForm: React.FC<LoginFormProps> = ({ onSwitchToRegister, onSwitchToForgotPassword, successMessage: externalSuccessMessage }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState(externalSuccessMessage || '');

  // --- Verification state (for unverified accounts) ---
  const [showVerification, setShowVerification] = useState(false);
  const [verificationCode, setVerificationCode] = useState('');
  const [unverifiedEmail, setUnverifiedEmail] = useState('');
  const [isResending, setIsResending] = useState(false);

  const { login, confirmRegistration, authMode } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccessMessage('');
    setIsLoading(true);

    try {
      await login(email, password);
      navigate('/', { replace: true });
    } catch (err: any) {
      const code = err?.code || err?.name || '';

      if (code === 'UserNotConfirmedException') {
        // Redirect to inline verification form (Cognito only)
        setUnverifiedEmail(email);
        setShowVerification(true);
      } else {
        // Handle both Cognito and local auth errors
        const message = err?.response?.data?.error || err?.message || 'Invalid email or password.';
        setError(message);
      }
    } finally {
      setIsLoading(false);
    }
  };

  // --- Verification code handler ---
  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccessMessage('');

    if (!verificationCode.trim()) {
      setError('Please enter the verification code');
      return;
    }

    setIsLoading(true);
    try {
      await confirmRegistration(unverifiedEmail, verificationCode.trim());
      setSuccessMessage('Email verified successfully! You can now log in.');
      setShowVerification(false);
      setVerificationCode('');
      setPassword('');
    } catch (err: any) {
      const code = err?.code || err?.name || '';
      if (code === 'CodeMismatchException') {
        setError('Invalid verification code. Please check and try again.');
      } else if (code === 'ExpiredCodeException') {
        setError('Verification code has expired. Please request a new one.');
      } else {
        setError(err?.message || 'Verification failed. Please try again.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  // --- Resend code handler ---
  const handleResendCode = async () => {
    setError('');
    setSuccessMessage('');
    setIsResending(true);
    try {
      await cognitoService.resendConfirmationCode(unverifiedEmail);
      setSuccessMessage('A new verification code has been sent to your email.');
    } catch (err: any) {
      setError(err?.message || 'Failed to resend code. Please try again.');
    } finally {
      setIsResending(false);
    }
  };

  // ===================== Verification Code View =====================
  if (showVerification) {
    return (
      <div className="auth-form">
        <h2>Verify Your Email</h2>
        <p className="verification-info">
          Your account is not yet verified. We sent a verification code to{' '}
          <strong>{unverifiedEmail}</strong>. Please enter it below.
        </p>

        {error && <div className="error-message">{error}</div>}
        {successMessage && <div className="success-message">{successMessage}</div>}

        <form onSubmit={handleVerify}>
          <div className="form-group">
            <label htmlFor="verificationCode">Verification Code</label>
            <input
              type="text"
              id="verificationCode"
              value={verificationCode}
              onChange={(e) => setVerificationCode(e.target.value)}
              required
              disabled={isLoading}
              placeholder="Enter 6-digit code"
              autoComplete="one-time-code"
              inputMode="numeric"
              maxLength={10}
              aria-describedby="verification-help"
            />
            <small id="verification-help" className="password-requirements">
              Check your email inbox (and spam folder) for the code.
            </small>
          </div>

          <button type="submit" className="auth-button" disabled={isLoading}>
            {isLoading ? 'Verifying…' : 'Verify Email'}
          </button>
        </form>

        <div className="auth-switch">
          <p>
            Didn't receive the code?{' '}
            <button
              type="button"
              className="link-button"
              onClick={handleResendCode}
              disabled={isResending || isLoading}
            >
              {isResending ? 'Sending…' : 'Resend code'}
            </button>
          </p>
          <p>
            <button
              type="button"
              className="link-button"
              onClick={() => {
                setShowVerification(false);
                setError('');
                setSuccessMessage('');
                setVerificationCode('');
              }}
              disabled={isLoading}
            >
              Back to login
            </button>
          </p>
        </div>
      </div>
    );
  }

  // ===================== Login Form View =====================
  return (
    <div className="auth-form">
      <h2>Login to AWS Practice Tests</h2>

      {error && <div className="error-message">{error}</div>}
      {successMessage && <div className="success-message">{successMessage}</div>}

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="email">Email</label>
          <input
            type="email"
            id="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            disabled={isLoading}
            placeholder="Enter your email"
          />
        </div>

        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            disabled={isLoading}
            placeholder="Enter your password"
          />
        </div>

        <button
          type="submit"
          className="auth-button"
          disabled={isLoading}
        >
          {isLoading ? 'Logging in...' : 'Login'}
        </button>
      </form>

      <div className="auth-switch">
        {onSwitchToForgotPassword && authMode === 'cognito' && (
          <p>
            <button
              type="button"
              className="link-button"
              onClick={onSwitchToForgotPassword}
              disabled={isLoading}
            >
              Forgot password?
            </button>
          </p>
        )}
        <p>
          Don't have an account?{' '}
          <button
            type="button"
            className="link-button"
            onClick={onSwitchToRegister}
            disabled={isLoading}
          >
            Register here
          </button>
        </p>
      </div>
    </div>
  );
};

export default LoginForm;
