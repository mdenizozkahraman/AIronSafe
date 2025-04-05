import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { HiOutlineCode, HiOutlineGlobe, HiOutlineDocumentReport, HiArrowRight, HiOutlineMoon, HiOutlineSun } from 'react-icons/hi';

const HomePage = () => {
  const [darkMode, setDarkMode] = useState(localStorage.getItem('darkMode') === 'true' || false);
  
  useEffect(() => {
    // Apply dark mode to the document
    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    localStorage.setItem('darkMode', darkMode);
  }, [darkMode]);

  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
  };

  return (
    <div className="min-h-screen flex flex-col bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
      {/* Navigation */}
      <nav className="bg-white dark:bg-gray-800 shadow-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex">
              <div className="flex-shrink-0 flex items-center">
                <h1 className="text-2xl font-bold text-green-600 dark:text-green-400">AIronSafe</h1>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <button
                onClick={toggleDarkMode}
                className="p-2 rounded-full text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700"
              >
                {darkMode ? (
                  <HiOutlineSun className="h-5 w-5" />
                ) : (
                  <HiOutlineMoon className="h-5 w-5" />
                )}
              </button>
              <Link 
                to="/login" 
                className="px-4 py-2 rounded-md text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700"
              >
                Sign In
              </Link>
              <Link 
                to="/register" 
                className="px-4 py-2 rounded-md bg-green-600 text-white hover:bg-green-700 dark:bg-green-700 dark:hover:bg-green-800"
              >
                Register
              </Link>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="bg-gradient-to-b from-gray-50 to-white dark:from-gray-900 dark:to-gray-800 py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <h1 className="text-4xl md:text-5xl font-bold text-gray-900 dark:text-white mb-4">
              Security Testing <span className="text-green-600 dark:text-green-400">Simplified</span>
            </h1>
            <p className="text-xl text-gray-600 dark:text-gray-300 max-w-3xl mx-auto mb-8">
              AIronSafe combines Static (SAST) and Dynamic (DAST) security testing in one comprehensive platform
            </p>
            <div className="flex flex-col sm:flex-row justify-center gap-4">
              <Link 
                to="/register" 
                className="px-6 py-3 rounded-lg bg-green-600 text-white hover:bg-green-700 dark:bg-green-700 dark:hover:bg-green-800 flex items-center justify-center shadow-lg"
              >
                Get Started <HiArrowRight className="ml-2" />
              </Link>
              <a 
                href="#learn-more" 
                className="px-6 py-3 rounded-lg border border-gray-300 dark:border-gray-600 hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center justify-center shadow-lg"
              >
                Learn More
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="learn-more" className="py-16 bg-white dark:bg-gray-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
              What is AIronSafe?
            </h2>
            <p className="text-gray-600 dark:text-gray-300 max-w-3xl mx-auto">
              AIronSafe is a comprehensive web application security testing platform that combines SAST and DAST capabilities in a modern, user-friendly interface.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            <div className="bg-gray-50 dark:bg-gray-700 p-6 rounded-lg shadow-md">
              <div className="text-green-600 dark:text-green-400 mb-4">
                <HiOutlineCode className="h-10 w-10" />
              </div>
              <h3 className="text-xl font-semibold mb-2">SAST Capabilities</h3>
              <p className="text-gray-600 dark:text-gray-300">
                Upload and analyze your source code for security vulnerabilities. AIronSafe supports multiple file formats and provides detailed vulnerability reports.
              </p>
              <ul className="mt-4 space-y-2 text-gray-600 dark:text-gray-300">
                <li className="flex items-start">
                  <span className="mr-2">•</span>
                  <span>Source code analysis</span>
                </li>
                <li className="flex items-start">
                  <span className="mr-2">•</span>
                  <span>Support for multiple file formats</span>
                </li>
                <li className="flex items-start">
                  <span className="mr-2">•</span>
                  <span>Severity-based categorization</span>
                </li>
              </ul>
            </div>

            <div className="bg-gray-50 dark:bg-gray-700 p-6 rounded-lg shadow-md">
              <div className="text-green-600 dark:text-green-400 mb-4">
                <HiOutlineGlobe className="h-10 w-10" />
              </div>
              <h3 className="text-xl font-semibold mb-2">DAST Capabilities</h3>
              <p className="text-gray-600 dark:text-gray-300">
                Test your live web applications by scanning them for vulnerabilities. Simply specify the URL and AIronSafe will handle the rest.
              </p>
              <ul className="mt-4 space-y-2 text-gray-600 dark:text-gray-300">
                <li className="flex items-start">
                  <span className="mr-2">•</span>
                  <span>Web application scanning</span>
                </li>
                <li className="flex items-start">
                  <span className="mr-2">•</span>
                  <span>URL-based target specification</span>
                </li>
                <li className="flex items-start">
                  <span className="mr-2">•</span>
                  <span>Comprehensive security assessment</span>
                </li>
              </ul>
            </div>

            <div className="bg-gray-50 dark:bg-gray-700 p-6 rounded-lg shadow-md">
              <div className="text-green-600 dark:text-green-400 mb-4">
                <HiOutlineDocumentReport className="h-10 w-10" />
              </div>
              <h3 className="text-xl font-semibold mb-2">Reporting & Analytics</h3>
              <p className="text-gray-600 dark:text-gray-300">
                Get detailed insights into your application's security posture with comprehensive reports and analytics.
              </p>
              <ul className="mt-4 space-y-2 text-gray-600 dark:text-gray-300">
                <li className="flex items-start">
                  <span className="mr-2">•</span>
                  <span>Detailed vulnerability descriptions</span>
                </li>
                <li className="flex items-start">
                  <span className="mr-2">•</span>
                  <span>Dashboard with key metrics</span>
                </li>
                <li className="flex items-start">
                  <span className="mr-2">•</span>
                  <span>Actionable remediation advice</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-16 bg-green-600 dark:bg-green-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl font-bold text-white mb-4">
            Ready to Secure Your Applications?
          </h2>
          <p className="text-green-100 max-w-3xl mx-auto mb-8">
            Join thousands of developers and security professionals who trust AIronSafe.
          </p>
          <Link 
            to="/register" 
            className="inline-block px-6 py-3 rounded-lg bg-white text-green-600 hover:bg-gray-100 shadow-lg"
          >
            Create Your Free Account <HiArrowRight className="inline ml-1" />
          </Link>
        </div>
      </section>

      {/* Copyright Section */}
      <section className="bg-gray-800 dark:bg-gray-950 text-gray-300 dark:text-gray-400 py-3 mt-auto">
        <div className="max-w-7xl mx-auto px-4">
          <div className="text-center">
            <p className="text-sm">© 2025 AIronSafe. All Rights Reserved.</p>
          </div>
        </div>
      </section>
    </div>
  );
};

export default HomePage; 