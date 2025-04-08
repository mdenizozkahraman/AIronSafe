const API_URL = 'https://aironsafe.com/api';

export const register = async (username, email, password, fullName) => {
  try {
    console.log('Sending registration request:', {
      username,
      email,
      password,
      full_name: fullName
    });

    const response = await fetch(`${API_URL}/api/users/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username,
        email,
        password,
        full_name: fullName
      }),
    });

    console.log('Registration response status:', response.status);
    
    const data = await response.json();
    console.log('Registration response data:', data);

    if (!response.ok) {
      throw new Error(data.message || 'Registration failed');
    }
    return data;
  } catch (error) {
    console.error('Registration error:', error);
    throw error;
  }
};

export const login = async (email, password) => {
  try {
    const response = await fetch(`${API_URL}/api/users/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email, password }),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.message || 'Login failed');
    }
    if (data.access_token) {
      localStorage.setItem('token', data.access_token);
    }
    return data;
  } catch (error) {
    console.error('Login error:', error);
    throw error;
  }
};
