import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  HiOutlineHome, 
  HiOutlineCode, 
  HiOutlineGlobe, 
  HiOutlineUser, 
  HiOutlineMoon, 
  HiOutlineSun, 
  HiOutlineLogout
} from 'react-icons/hi';

const Layout = ({ children, userName, darkMode, toggleDarkMode, handleLogout }) => {
  const location = useLocation();
  const currentPath = location.pathname;

  const getPageTitle = () => {
    switch (currentPath) {
      case '/dashboard':
        return 'Dashboard';
      case '/sast':
        return 'SAST';
      case '/dast':
        return 'DAST';
      case '/profile':
        return 'Profile';
      default:
        return '';
    }
  };

  return (
    <div className="flex flex-col min-h-screen bg-gray-100 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
      {/* Header */}
      <header className="fixed top-0 left-0 right-0 bg-white dark:bg-gray-800 shadow-md dark:shadow-gray-900 p-4 text-center text-3xl font-bold text-green-600 dark:text-green-400 z-10 border-b border-gray-200 dark:border-gray-900">
        AIronSafe
      </header>

      {/* Main Content Area with Sidebar */}
      <div className="flex flex-1 pt-16 pb-16">
        {/* Left Sidebar */}
        <aside className="fixed left-0 top-16 bottom-16 w-64 bg-white dark:bg-gray-800 p-4 border-r border-gray-200 dark:border-gray-700 shadow-sm overflow-y-auto">
          <nav className="space-y-4 mt-4">
            <Link 
              to="/dashboard" 
              className={`flex items-center px-3 py-2 rounded transition-colors ${
                currentPath === '/dashboard' 
                  ? 'bg-gray-200 dark:bg-gray-700 font-bold' 
                  : 'hover:bg-gray-100 dark:hover:bg-gray-700'
              }`}
            >
              <HiOutlineHome className="mr-2 h-5 w-5" />
              Dashboard
            </Link>
            <Link 
              to="/sast" 
              className={`flex items-center px-3 py-2 rounded transition-colors ${
                currentPath === '/sast' 
                  ? 'bg-gray-200 dark:bg-gray-700 font-bold' 
                  : 'hover:bg-gray-100 dark:hover:bg-gray-700'
              }`}
            >
              <HiOutlineCode className="mr-2 h-5 w-5" />
              SAST
            </Link>
            <Link 
              to="/dast" 
              className={`flex items-center px-3 py-2 rounded transition-colors ${
                currentPath === '/dast' 
                  ? 'bg-gray-200 dark:bg-gray-700 font-bold' 
                  : 'hover:bg-gray-100 dark:hover:bg-gray-700'
              }`}
            >
              <HiOutlineGlobe className="mr-2 h-5 w-5" />
              DAST
            </Link>
          </nav>
          <div className="absolute bottom-4 left-4 right-4 flex items-center justify-between">
            <button 
              onClick={toggleDarkMode} 
              className="group relative p-2 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              aria-label="Toggle Dark Mode"
            >
              {darkMode ? <HiOutlineSun className="h-5 w-5" /> : <HiOutlineMoon className="h-5 w-5" />}
              <span className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-2 py-1 text-xs font-medium text-white bg-gray-900 rounded-md opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                {darkMode ? 'Light Mode' : 'Dark Mode'}
              </span>
            </button>
            <Link 
              to="/profile" 
              className="group relative p-2 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              aria-label="Profile"
            >
              <HiOutlineUser className="h-5 w-5" />
              <span className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-2 py-1 text-xs font-medium text-white bg-gray-900 rounded-md opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                Profile
              </span>
            </Link>
            <button 
              onClick={handleLogout} 
              className="group relative p-2 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              aria-label="Logout"
            >
              <HiOutlineLogout className="h-5 w-5" />
              <span className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-2 py-1 text-xs font-medium text-white bg-gray-900 rounded-md opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                Logout
              </span>
            </button>
          </div>
        </aside>

        {/* Main Content */}
        <main className="ml-64 flex-1 p-6 pt-4 overflow-y-auto">
          <div className="bg-white dark:bg-gray-800 shadow p-4 flex justify-between items-center mb-6 rounded-lg">
            <h1 id="page-title" className="text-lg font-semibold">{getPageTitle()}</h1>
            <div className="flex items-center space-x-4 md:hidden">
              <button onClick={toggleDarkMode} aria-label="Toggle Dark Mode" className="group relative">
                {darkMode ? <HiOutlineSun className="h-5 w-5" /> : <HiOutlineMoon className="h-5 w-5" />}
                <span className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-2 py-1 text-xs font-medium text-white bg-gray-900 rounded-md opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                  {darkMode ? 'Light Mode' : 'Dark Mode'}
                </span>
              </button>
              <Link to="/profile" className="group relative hover:underline">
                <HiOutlineUser className="h-5 w-5" />
                <span className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-2 py-1 text-xs font-medium text-white bg-gray-900 rounded-md opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                  Profile
                </span>
              </Link>
              <button onClick={handleLogout} aria-label="Logout" className="group relative">
                <HiOutlineLogout className="h-5 w-5" />
                <span className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-2 py-1 text-xs font-medium text-white bg-gray-900 rounded-md opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                  Logout
                </span>
              </button>
            </div>
          </div>
          <div className="container mx-auto">
            {children}
          </div>
        </main>
      </div>

      {/* Footer */}
      <footer className="fixed bottom-0 left-0 right-0 bg-white dark:bg-gray-800 text-center text-sm py-4 border-t border-gray-200 dark:border-gray-700 z-10">
        © 2025 AIronSafe. All Rights Reserved.
      </footer>
    </div>
  );
};

export default Layout; 