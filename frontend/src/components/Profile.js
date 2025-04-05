import React, { useState, useEffect } from 'react';
import { HiOutlinePencil, HiOutlineCheck, HiOutlineX, HiOutlineLockClosed } from 'react-icons/hi';

const Profile = () => {
  const [userData, setUserData] = useState({
    username: '',
    email: ''
  });
  const [passwordData, setPasswordData] = useState({
    newPassword: '',
    confirmPassword: ''
  });
  const [isEditing, setIsEditing] = useState(false);
  const [isChangingPassword, setIsChangingPassword] = useState(false);
  const [error, setError] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [updateSuccess, setUpdateSuccess] = useState(false);
  const [passwordUpdateSuccess, setPasswordUpdateSuccess] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Try to get user data from localStorage first
    const storedUser = localStorage.getItem('user');
    
    if (storedUser) {
      try {
        const parsedUser = JSON.parse(storedUser);
        setUserData({
          username: parsedUser.username || '',
          email: parsedUser.email || ''
        });
        setLoading(false);
      } catch (err) {
        console.error('Error parsing stored user data:', err);
        fetchUserFromAPI();
      }
    } else {
      fetchUserFromAPI();
    }
  }, []);

  const fetchUserFromAPI = async () => {
    try {
      const token = localStorage.getItem('token');
      
      if (!token) {
        setError('Authentication token not found. Please log in again.');
        setLoading(false);
        return;
      }
      
      const response = await fetch('http://localhost:5000/api/users/me', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.message || 'Failed to fetch user data');
      }
      
      setUserData({
        username: data.username || '',
        email: data.email || ''
      });
    } catch (err) {
      console.error('Error fetching user data:', err);
      setError('Failed to load profile data. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = () => {
    setIsEditing(true);
    setError('');
    setUpdateSuccess(false);
  };

  const handleCancel = () => {
    setIsEditing(false);
    setError('');
    setUpdateSuccess(false);
  };

  const handlePasswordChange = () => {
    setIsChangingPassword(true);
    setPasswordError('');
    setPasswordUpdateSuccess(false);
  };

  const handlePasswordCancel = () => {
    setIsChangingPassword(false);
    setPasswordError('');
    setPasswordUpdateSuccess(false);
    setPasswordData({
      newPassword: '',
      confirmPassword: ''
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setUpdateSuccess(false);

    try {
      const token = localStorage.getItem('token');
      
      if (!token) {
        setError('Authentication token not found. Please log in again.');
        return;
      }
      
      const response = await fetch('http://localhost:5000/api/profile', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          username: userData.username,
          email: userData.email
        })
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.message || 'Failed to update profile');
      }
      
      // Update localStorage with new user data
      localStorage.setItem('user', JSON.stringify({
        username: userData.username,
        email: userData.email
      }));
      
      setUpdateSuccess(true);
      setIsEditing(false);
    } catch (err) {
      console.error('Error updating profile:', err);
      setError(err.message || 'Failed to update profile. Please try again.');
    }
  };

  const handlePasswordSubmit = async (e) => {
    e.preventDefault();
    setPasswordError('');
    setPasswordUpdateSuccess(false);

    // Validate passwords
    if (passwordData.newPassword !== passwordData.confirmPassword) {
      setPasswordError('New passwords do not match');
      return;
    }

    if (passwordData.newPassword.length < 6) {
      setPasswordError('Password must be at least 6 characters long');
      return;
    }

    try {
      // Get user information
      const userStr = localStorage.getItem('user');
      if (!userStr) {
        setPasswordError('User information not found. Please log in again.');
        return;
      }
      
      const user = JSON.parse(userStr);
      console.log('User information:', user);
      
      // Use simple password change endpoint independent of token issues
      const response = await fetch('http://localhost:5000/api/users/simple-change-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          email: user.email,
          new_password: passwordData.newPassword
        })
      });
      
      console.log('Password update response status:', response.status);
      
      if (response.status === 404) {
        setPasswordError('User not found. Please log in again.');
        return;
      }
      
      let data;
      try {
        data = await response.json();
        console.log('Password update response data:', data);
      } catch (err) {
        console.error('Error parsing response:', err);
        if (response.status >= 200 && response.status < 300) {
          // If status is success but no JSON, still treat as success
          setPasswordUpdateSuccess(true);
          setIsChangingPassword(false);
          setPasswordData({
            newPassword: '',
            confirmPassword: ''
          });
          return;
        }
        throw new Error('Server returned an invalid response');
      }
      
      if (!response.ok) {
        throw new Error(data.message || 'Failed to update password');
      }
      
      setPasswordUpdateSuccess(true);
      setIsChangingPassword(false);
      setPasswordData({
        newPassword: '',
        confirmPassword: ''
      });
    } catch (err) {
      console.error('Error updating password:', err);
      setPasswordError(err.message || 'Failed to update password. Please try again.');
    }
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setUserData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handlePasswordDataChange = (e) => {
    const { name, value } = e.target;
    setPasswordData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* User Information Section */}
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-lg font-semibold">Profile Information</h2>
          {/* Edit Profile button removed temporarily */}
        </div>

        {error && (
          <div className="mb-4 p-4 bg-red-50 dark:bg-red-900/30 rounded-lg">
            <p className="text-sm text-red-800 dark:text-red-400">{error}</p>
          </div>
        )}

        {updateSuccess && (
          <div className="mb-4 p-4 bg-green-50 dark:bg-green-900/30 rounded-lg">
            <p className="text-sm text-green-800 dark:text-green-400">Profile updated successfully!</p>
          </div>
        )}

        {isEditing ? (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Username
              </label>
              <input
                type="text"
                id="username"
                name="username"
                value={userData.username}
                onChange={handleChange}
                className="w-full px-4 py-2 rounded-lg border border-gray-200 dark:border-gray-600 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white transition-colors duration-200"
                required
              />
            </div>

            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Email
              </label>
              <input
                type="email"
                id="email"
                name="email"
                value={userData.email}
                onChange={handleChange}
                className="w-full px-4 py-2 rounded-lg border border-gray-200 dark:border-gray-600 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white transition-colors duration-200"
                required
              />
            </div>

            <div className="flex space-x-4">
              <button
                type="submit"
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 dark:bg-blue-700 dark:hover:bg-blue-800 transition-colors duration-200"
              >
                <HiOutlineCheck className="inline mr-1 h-4 w-4" /> Save Changes
              </button>
              <button
                type="button"
                onClick={handleCancel}
                className="px-4 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600 transition-colors duration-200"
              >
                <HiOutlineX className="inline mr-1 h-4 w-4" /> Cancel
              </button>
            </div>
          </form>
        ) : (
          <div className="space-y-4">
            <div className="border-b border-gray-200 dark:border-gray-700 pb-3">
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Username</p>
              <p className="mt-1 text-gray-900 dark:text-white">{userData.username}</p>
            </div>

            <div className="border-b border-gray-200 dark:border-gray-700 pb-3">
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Email</p>
              <p className="mt-1 text-gray-900 dark:text-white">{userData.email}</p>
            </div>
          </div>
        )}
      </div>

      {/* Password Change Section */}
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-lg font-semibold">Change Password</h2>
          {!isChangingPassword && (
            <button
              onClick={handlePasswordChange}
              className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 dark:bg-green-700 dark:hover:bg-green-800 transition-colors duration-200"
            >
              <HiOutlineLockClosed className="inline mr-1 h-4 w-4" /> Change Password
            </button>
          )}
        </div>

        {passwordError && (
          <div className="mb-4 p-4 bg-red-50 dark:bg-red-900/30 rounded-lg">
            <p className="text-sm text-red-800 dark:text-red-400">{passwordError}</p>
          </div>
        )}

        {passwordUpdateSuccess && (
          <div className="mb-4 p-4 bg-green-50 dark:bg-green-900/30 rounded-lg">
            <p className="text-sm text-green-800 dark:text-green-400">Password updated successfully!</p>
          </div>
        )}

        {isChangingPassword ? (
          <form onSubmit={handlePasswordSubmit} className="space-y-4">
            <div>
              <label htmlFor="newPassword" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                New Password
              </label>
              <input
                type="password"
                id="newPassword"
                name="newPassword"
                value={passwordData.newPassword}
                onChange={handlePasswordDataChange}
                className="w-full px-4 py-2 rounded-lg border border-gray-200 dark:border-gray-600 focus:ring-2 focus:ring-green-500 focus:border-green-500 dark:bg-gray-700 dark:text-white transition-colors duration-200"
                required
              />
            </div>

            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Confirm New Password
              </label>
              <input
                type="password"
                id="confirmPassword"
                name="confirmPassword"
                value={passwordData.confirmPassword}
                onChange={handlePasswordDataChange}
                className="w-full px-4 py-2 rounded-lg border border-gray-200 dark:border-gray-600 focus:ring-2 focus:ring-green-500 focus:border-green-500 dark:bg-gray-700 dark:text-white transition-colors duration-200"
                required
              />
            </div>

            <div className="flex space-x-4">
              <button
                type="submit"
                className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 dark:bg-green-700 dark:hover:bg-green-800 transition-colors duration-200"
              >
                <HiOutlineCheck className="inline mr-1 h-4 w-4" /> Update Password
              </button>
              <button
                type="button"
                onClick={handlePasswordCancel}
                className="px-4 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600 transition-colors duration-200"
              >
                <HiOutlineX className="inline mr-1 h-4 w-4" /> Cancel
              </button>
            </div>
          </form>
        ) : (
          <p className="text-gray-600 dark:text-gray-400">You can change your password to keep your account secure.</p>
        )}
      </div>
    </div>
  );
};

export default Profile; 