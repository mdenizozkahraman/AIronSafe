import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { HiOutlineMail, HiOutlineLockClosed, HiOutlineLogin } from 'react-icons/hi';

const Login = () => {
  const [credentials, setCredentials] = useState({
    email: '',
    password: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  // Debug amacıyla authentication durumunu kontrol et
  useEffect(() => {
    const token = localStorage.getItem('token');
    console.log('Component yüklendiğinde token:', token);
    
    if (token) {
      console.log('Token var, otomatik olarak dashboard\'a yönlendirilecek');
      // Redirect to dashboard with a delay to avoid potential race conditions
      setTimeout(() => {
        navigate('/dashboard');
      }, 100);
    }
  }, [navigate]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setCredentials(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    if (!credentials.email || !credentials.password) {
      setError('Please fill in all fields');
      return;
    }

    setLoading(true);
    console.log('Giriş isteği gönderiliyor...');
    
    try {
      const response = await fetch('http://localhost:5000/api/users/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ 
          email: credentials.email, 
          password: credentials.password 
        })
      });
      
      console.log('Sunucu yanıtı alındı, status:', response.status);
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.message || 'Login failed');
      }
      
      console.log('Login başarılı, yanıt:', data);
      
      // Store the token and user data, then navigate to dashboard
      const token = data.access_token;
      
      if (!token) {
        throw new Error('No token received from server');
      }
      
      console.log('Token alındı:', token);
      
      // Reset any previous authentication data
      localStorage.clear();
      
      // Save new authentication data
      localStorage.setItem('token', token);
      
      // Save user information
      if (data.user) {
        console.log('Kullanıcı bilgileri alındı:', data.user);
        localStorage.setItem('user', JSON.stringify(data.user));
      }
      
      console.log('Veriler localStorage\'a kaydedildi, dashboard\'a yönlendiriliyor...');
      
      // Navigate with a slight delay to ensure localStorage is updated
      setTimeout(() => {
        window.location.href = '/dashboard'; // Force full page refresh to apply auth state
      }, 100);
    } catch (err) {
      console.error('Login error:', err);
      setError(err.message || 'Login failed. Please try again.');
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

        {/* Login Card */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-8">
          <h2 className="text-2xl font-semibold mb-6 text-gray-800 dark:text-white text-center">Sign In</h2>
          
          {error && (
            <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 rounded-lg text-sm">
              {error}
            </div>
          )}

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
                  value={credentials.email}
                  onChange={handleChange}
                  className="flex-1 py-2 px-4 bg-white dark:bg-gray-700 outline-none text-gray-900 dark:text-white w-full"
                  placeholder="you@example.com"
                />
              </div>
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Password
              </label>
              <div className="flex overflow-hidden rounded-lg border border-gray-300 dark:border-gray-600 focus-within:ring-2 focus-within:ring-green-500 focus-within:border-green-500">
                <div className="flex items-center justify-center bg-gray-100 dark:bg-gray-700 px-3">
                  <HiOutlineLockClosed className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  id="password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={credentials.password}
                  onChange={handleChange}
                  className="flex-1 py-2 px-4 bg-white dark:bg-gray-700 outline-none text-gray-900 dark:text-white w-full"
                  placeholder="••••••••"
                />
              </div>
              <div className="flex justify-end mt-2">
                <Link to="/forgot-password" className="text-sm text-green-600 hover:text-green-500 dark:text-green-400 dark:hover:text-green-300">
                  Forgot password?
                </Link>
              </div>
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
                    Signing in...
                  </>
                ) : (
                  <>
                    <HiOutlineLogin className="mr-2 h-5 w-5" />
                    Sign In
                  </>
                )}
              </button>
            </div>
          </form>
        </div>

        {/* Register Link */}
        <div className="text-center mt-6">
          <p className="text-gray-600 dark:text-gray-400">
            Don't have an account?{' '}
            <Link to="/register" className="font-medium text-green-600 hover:text-green-500 dark:text-green-400 dark:hover:text-green-300">
              Sign up
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;
