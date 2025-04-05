import React, { useState } from 'react';
import { HiOutlineSearch } from 'react-icons/hi';

const DAST = () => {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);

  const handleUrlChange = (e) => {
    setUrl(e.target.value);
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!url) return;
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      alert('Please enter a valid URL starting with http:// or https://');
      return;
    }

    setScanning(true);
    
    // Simulate scan process
    setTimeout(() => {
      setScanning(false);
      setUrl('');
      
      // Here you would actually send the URL to your backend
      alert('Scan started for: ' + url);
    }, 2000);
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
        <h2 className="text-lg font-semibold mb-4">Start New DAST Scan</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="text"
            value={url}
            onChange={handleUrlChange}
            placeholder="https://example.com"
            className="w-full px-4 py-2 rounded-lg border border-gray-200 dark:border-gray-600 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white transition-colors duration-200"
          />
          <button
            type="submit"
            disabled={!url || scanning}
            className={`w-full py-3 px-4 flex justify-center items-center rounded-lg font-medium text-white
              ${!url || scanning ? 'bg-gray-400 dark:bg-gray-600 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700 dark:bg-blue-700 dark:hover:bg-blue-800'}
              transition-colors duration-200`}
          >
            {scanning ? (
              <>
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Scanning...
              </>
            ) : (
              <>
                <HiOutlineSearch className="mr-2 h-5 w-5" />
                Start Scan
              </>
            )}
          </button>
        </form>
      </div>

      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-lg font-semibold">DAST Scan History</h2>
          <button className="bg-green-600 hover:bg-green-700 text-white px-3 py-1 rounded transition-colors">
            📄 Download Report
          </button>
        </div>
        <div className="mb-4">
          <input 
            type="text" 
            placeholder="Search by URL..." 
            className="w-full p-2 rounded bg-gray-100 dark:bg-gray-700 border border-gray-200 dark:border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-gray-200 dark:border-gray-700">
                <th className="py-3 pr-6">URL</th>
                <th className="py-3 pr-6">Date</th>
                <th className="py-3 pr-6">Status</th>
                <th className="py-3">CVSS</th>
              </tr>
            </thead>
            <tbody className="divide-y dark:divide-gray-700">
              <tr className="hover:bg-gray-50 dark:hover:bg-gray-800/60">
                <td className="py-3 pr-6">https://example.com</td>
                <td className="py-3 pr-6">14 Eyl 2023</td>
                <td className="py-3 pr-6">
                  <span className="text-green-500 dark:text-green-400">Completed</span>
                </td>
                <td className="py-3">
                  <span className="bg-red-600 text-white px-2 py-1 rounded text-xs">9.1</span>
                </td>
              </tr>
              <tr className="hover:bg-gray-50 dark:hover:bg-gray-800/60">
                <td className="py-3 pr-6">https://staging.site</td>
                <td className="py-3 pr-6">10 Eyl 2023</td>
                <td className="py-3 pr-6">
                  <span className="text-red-500 dark:text-red-400">Failed</span>
                </td>
                <td className="py-3">
                  <span className="bg-gray-600 text-white px-2 py-1 rounded text-xs">—</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default DAST;
