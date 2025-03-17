import React, { useState } from 'react';
import Login from './components/Login';
import Register from './components/Register';

const App = () => {
  const [showLogin, setShowLogin] = useState(true);

  const switchToRegister = () => setShowLogin(false);
  const switchToLogin = () => setShowLogin(true);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      {/* Başlık */}
      <header>
        AIronSafe
      </header>

      {/* Login / Register */}
      <div>
        {showLogin ? (
          <Login switchToRegister={switchToRegister} />
        ) : (
          <Register switchToLogin={switchToLogin} />
        )}
      </div>

      {/* Footer */}
      <footer>
        © 2024 AIronSafe. All Rights Reserved.
      </footer>
    </div>
  );
};

export default App;
