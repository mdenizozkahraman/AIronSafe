import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { HiOutlineMail, HiOutlineArrowLeft, HiOutlinePaperAirplane, HiOutlineLockClosed } from 'react-icons/hi';

const ForgotPassword = () => {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const navigate = useNavigate();

  const handleChange = (e) => {
    setEmail(e.target.value);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess(false);
    setNewPassword('');
    
    if (!email) {
      setError('Please enter your email address');
      return;
    }

    setLoading(true);
    
    try {
      const response = await fetch('http://localhost:5000/api/users/forgot-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email })
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.message || 'Failed to reset password');
      }
      
      setSuccess(true);
      setNewPassword(data.new_password);
    } catch (err) {
      console.error('Error resetting password:', err);
      setError(err.message || 'Something went wrong. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900 px-4">
      <div className="max-w-md w-full">
        {/* Logo/Header */}
        <div className="text-center mb-10">
          <h1 className="text-3xl font-bold text-green-600 dark:text-green-400 mb-2">AIronSafe</h1>
          <p className="text-gray-600 dark:text-gray-400">Security Testing Platform</p>
        </div>

        {/* Forgot Password Card */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-8">
          <h2 className="text-2xl font-semibold mb-6 text-gray-800 dark:text-white text-center">Reset Password</h2>
          
          {error && (
            <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 rounded-lg text-sm">
              {error}
            </div>
          )}

          {success ? (
            <div className="space-y-6">
              <div className="p-4 bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 rounded-lg">
                <p className="text-center mb-2">Your password has been reset successfully!</p>
                {newPassword && (
                  <div className="mt-4">
                    <p className="text-center font-semibold mb-1">Your new password is:</p>
                    <div className="flex items-center justify-center space-x-2 bg-white dark:bg-gray-700 p-3 rounded-lg border border-green-200 dark:border-green-900">
                      <HiOutlineLockClosed className="text-green-600 dark:text-green-400" />
                      <span className="font-mono text-lg">{newPassword}</span>
                    </div>
                    <p className="text-xs text-center mt-2">Please use this password to log in and change it immediately for security reasons.</p>
                  </div>
                )}
              </div>
              <button
                onClick={() => navigate('/login')}
                className="w-full flex justify-center items-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 transition-colors dark:bg-green-700 dark:hover:bg-green-800"
              >
                <HiOutlineArrowLeft className="mr-2 h-5 w-5" />
                Go to Sign In
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-6">
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Email
                </label>
                <div className="flex overflow-hidden rounded-lg border border-gray-300 dark:border-gray-600 focus-within:ring-2 focus-within:ring-green-500 focus-within:border-green-500">
                  <div className="flex items-center justify-center bg-gray-100 dark:bg-gray-700 px-3">
                    <HiOutlineMail className="h-5 w-5 text-gray-400" />
                  </div>
                  <input
                    id="email"
                    name="email"
                    type="email"
                    autoComplete="email"
                    required
                    value={email}
                    onChange={handleChange}
                    className="flex-1 py-2 px-4 bg-white dark:bg-gray-700 outline-none text-gray-900 dark:text-white w-full"
                    placeholder="you@example.com"
                  />
                </div>
                <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                  Enter the email address associated with your account, and we'll generate a new password for you.
                </p>
              </div>

              <div>
                <button
                  type="submit"
                  disabled={loading}
                  className={`w-full flex justify-center items-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 transition-colors dark:bg-green-700 dark:hover:bg-green-800 ${
                    loading ? 'opacity-70 cursor-not-allowed' : ''
                  }`}
                >
                  {loading ? (
                    <>
                      <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      Processing...
                    </>
                  ) : (
                    <>
                      <HiOutlinePaperAirplane className="mr-2 h-5 w-5" />
                      Reset Password
                    </>
                  )}
                </button>
              </div>
            </form>
          )}
        </div>

        {/* Login Link */}
        <div className="text-center mt-6">
          <p className="text-gray-600 dark:text-gray-400">
            <Link to="/login" className="font-medium text-green-600 hover:text-green-500 dark:text-green-400 dark:hover:text-green-300 flex items-center justify-center">
              <HiOutlineArrowLeft className="mr-1 h-4 w-4" />
              Back to Sign In
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default ForgotPassword; 