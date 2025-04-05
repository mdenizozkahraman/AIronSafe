import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const Logout = () => {
  const navigate = useNavigate();

  useEffect(() => {
    // Clear all authentication data
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    
    // Also clear any other app data to ensure a fresh start
    localStorage.clear();
    
    // Redirect to login page
    navigate('/login');
  }, [navigate]);

  return (
    <div className="flex items-center justify-center h-screen">
      <div className="text-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-green-500 mx-auto mb-4"></div>
        <h2 className="text-xl font-semibold text-gray-700 dark:text-gray-300">Logging out...</h2>
        <p className="text-gray-500 dark:text-gray-400 mt-2">You will be redirected to the login page.</p>
      </div>
    </div>
  );
};

export default Logout; 