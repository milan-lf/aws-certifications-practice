import React, { useState, useMemo } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { cognitoService } from '../../services/cognitoService';
import './AuthForms.css';

interface RegisterFormProps {
  onSwitchToLogin: () => void;
}

interface PasswordCheck {
  label: string;
  met: boolean;
}

function getPasswordChecks(password: string): PasswordCheck[] {
  return [
    { label: 'At least 8 characters', met: password.length >= 8 },
    { label: 'One uppercase letter', met: /[A-Z]/.test(password) },
    { label: 'One lowercase letter', met: /[a-z]/.test(password) },
    { label: 'One number', met: /\d/.test(password) },
    { label: 'One special character (!@#$%^&*…)', met: /[^A-Za-z0-9]/.test(password) },
  ];
}

const RegisterForm: React.FC<RegisterFormProps> = ({ onSwitchToLogin }) => {
  // --- Registration form state ---
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    firstName: '',
    lastName: '',
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  // --- Verification state ---
  const [showVerification, setShowVerification] = useState(false);
  const [verificationCode, setVerificationCode] = useState('');
  const [registeredEmail, setRegisteredEmail] = useState('');
  const [isResending, setIsResending] = useState(false);

  const { register, confirmRegistration, authMode } = useAuth();

  // --- Real-time password checks ---
  const passwordChecks = useMemo(
    () => getPasswordChecks(formData.password),
    [formData.password]
  );
  const allPasswordChecksMet = passwordChecks.every((c) => c.met);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  // --- Client-side validation ---
  const validateForm = (): boolean => {
    if (!allPasswordChecksMet) {
      setError('Password does not meet all requirements');
      return false;
    }
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return false;
    }
    return true;
  };

  // --- Signup handler ---
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccessMessage('');

    if (!validateForm()) return;

    setIsLoading(true);
    try {
      const result = await register(
        formData.email,
        formData.password,
        formData.firstName || undefined,
        formData.lastName || undefined
      );

      if (authMode === 'local') {
        // Local mode: user is auto-logged in, no verification needed
        setSuccessMessage('Account created successfully!');
        // The AuthContext already set the user, so the UI will redirect
        return;
      }

      // Cognito mode
      if (result && result.userConfirmed) {
        // Auto-confirmed (unlikely with email verification enabled)
        setSuccessMessage('Account created successfully! Redirecting to login…');
        setTimeout(() => onSwitchToLogin(), 1500);
      } else {
        // Show verification code form
        setRegisteredEmail(formData.email);
        setShowVerification(true);
      }
    } catch (err: any) {
      const code = err?.code || err?.name || '';
      const apiErrorCode = err?.response?.data?.error?.code || err?.response?.data?.code || '';
      if (code === 'UsernameExistsException' || apiErrorCode === 'EMAIL_EXISTS') {
        setError('An account with this email already exists. Please login instead.');
      } else {
        const apiError = err?.response?.data?.error;
        const message = (typeof apiError === 'object' ? apiError?.message : apiError)
          || err?.message
          || 'Registration failed. Please try again.';
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
      await confirmRegistration(registeredEmail, verificationCode.trim());
      setSuccessMessage('Email verified successfully! Redirecting to login…');
      setTimeout(() => onSwitchToLogin(), 1500);
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
      await cognitoService.resendConfirmationCode(registeredEmail);
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
          We sent a verification code to <strong>{registeredEmail}</strong>.
          Please enter it below to complete your registration.
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
              onClick={onSwitchToLogin}
              disabled={isLoading}
            >
              Back to login
            </button>
          </p>
        </div>
      </div>
    );
  }

  // ===================== Registration Form View =====================
  return (
    <div className="auth-form">
      <h2>Register for AWS Practice Tests</h2>

      {error && <div className="error-message">{error}</div>}
      {successMessage && <div className="success-message">{successMessage}</div>}

      <form onSubmit={handleSubmit}>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="firstName">First Name (Optional)</label>
            <input
              type="text"
              id="firstName"
              name="firstName"
              value={formData.firstName}
              onChange={handleChange}
              disabled={isLoading}
              placeholder="Enter your first name"
            />
          </div>
          <div className="form-group">
            <label htmlFor="lastName">Last Name (Optional)</label>
            <input
              type="text"
              id="lastName"
              name="lastName"
              value={formData.lastName}
              onChange={handleChange}
              disabled={isLoading}
              placeholder="Enter your last name"
            />
          </div>
        </div>

        <div className="form-group">
          <label htmlFor="email">Email *</label>
          <input
            type="email"
            id="email"
            name="email"
            value={formData.email}
            onChange={handleChange}
            required
            disabled={isLoading}
            placeholder="Enter your email"
          />
        </div>

        <div className="form-group">
          <label htmlFor="password">Password *</label>
          <input
            type="password"
            id="password"
            name="password"
            value={formData.password}
            onChange={handleChange}
            required
            disabled={isLoading}
            placeholder="Enter your password"
            aria-describedby="password-checks"
          />
          {/* Real-time password validation feedback */}
          {formData.password.length > 0 && (
            <ul className="password-checklist" id="password-checks" aria-label="Password requirements">
              {passwordChecks.map((check) => (
                <li key={check.label} className={check.met ? 'check-met' : 'check-unmet'}>
                  <span className="check-icon" aria-hidden="true">{check.met ? '✓' : '✗'}</span>
                  {check.label}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="form-group">
          <label htmlFor="confirmPassword">Confirm Password *</label>
          <input
            type="password"
            id="confirmPassword"
            name="confirmPassword"
            value={formData.confirmPassword}
            onChange={handleChange}
            required
            disabled={isLoading}
            placeholder="Confirm your password"
          />
        </div>

        <button type="submit" className="auth-button" disabled={isLoading}>
          {isLoading ? 'Creating Account…' : 'Register'}
        </button>
      </form>

      <div className="auth-switch">
        <p>
          Already have an account?{' '}
          <button
            type="button"
            className="link-button"
            onClick={onSwitchToLogin}
            disabled={isLoading}
          >
            Login here
          </button>
        </p>
      </div>
    </div>
  );
};

export default RegisterForm;
