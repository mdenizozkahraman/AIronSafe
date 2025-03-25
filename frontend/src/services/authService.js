const API_URL = 'http://localhost:5000';

export const register = async (username, email, password) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        message: 'User created successfully'
      });
    }, 1000);
  });
};

export const login = async (email, password) => {
  const response = await fetch(`${API_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const data = await response.json();
  if (data.access_token) {
    localStorage.setItem('token', data.access_token);
  }
  return data;
};
