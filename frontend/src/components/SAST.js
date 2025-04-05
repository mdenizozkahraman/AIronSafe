import React, { useState } from 'react';
import { HiOutlineUpload } from 'react-icons/hi';

const SAST = () => {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);

  const handleFileChange = (e) => {
    if (e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleFileUpload = (e) => {
    e.preventDefault();
    if (!file) return;

    setUploading(true);
    
    // Simulate upload process
    setTimeout(() => {
      setUploading(false);
      setFile(null);
      // Here you would actually send the file to your backend
      alert('File uploaded successfully! Scan started.');
    }, 2000);
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
        <h2 className="text-lg font-semibold mb-4">Upload Code for Analysis</h2>
        <form onSubmit={handleFileUpload} className="space-y-4">
          <div className="flex items-center justify-center w-full">
            <label 
              className={`flex flex-col items-center justify-center w-full h-48 border-2 border-dashed rounded-lg cursor-pointer ${
                file ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20' : 'border-gray-300 dark:border-gray-600 hover:bg-gray-100 dark:hover:bg-gray-700/30'
              } transition-all duration-200`}
            >
              <div className="flex flex-col items-center justify-center pt-5 pb-6">
                <HiOutlineUpload className={`w-10 h-10 mb-3 ${file ? 'text-blue-600 dark:text-blue-400' : 'text-gray-500 dark:text-gray-400'}`} />
                {file ? (
                  <p className="text-sm font-medium text-gray-700 dark:text-gray-300">
                    <span className="font-semibold text-blue-700 dark:text-blue-400">{file.name}</span>
                  </p>
                ) : (
                  <>
                    <p className="mb-2 text-sm font-medium text-gray-700 dark:text-gray-300">
                      <span className="font-semibold">Click to upload</span> or drag and drop
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      Supported file formats: ZIP, JS, PY, JAVA, etc.
                    </p>
                  </>
                )}
              </div>
              <input 
                id="dropzone-file" 
                type="file" 
                className="hidden" 
                onChange={handleFileChange}
                accept=".zip,.js,.py,.java,.jsx,.ts,.tsx"
              />
            </label>
          </div>
          <button
            type="submit"
            disabled={!file || uploading}
            className={`w-full py-3 px-4 flex justify-center items-center rounded-lg font-medium text-white
              ${!file || uploading ? 'bg-gray-400 dark:bg-gray-600 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700 dark:bg-blue-700 dark:hover:bg-blue-800'}
              transition-colors duration-200`}
          >
            {uploading ? (
              <>
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Uploading...
              </>
            ) : (
              'Start Scan'
            )}
          </button>
        </form>
      </div>

      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-lg font-semibold">SAST Scan History</h2>
          <button className="bg-green-600 hover:bg-green-700 text-white px-3 py-1 rounded transition-colors">
            📄 Download Report
          </button>
        </div>
        <div className="mb-4">
          <input 
            type="text" 
            placeholder="Search by file name..." 
            className="w-full p-2 rounded bg-gray-100 dark:bg-gray-700 border border-gray-200 dark:border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-gray-200 dark:border-gray-700">
                <th className="py-3 pr-6">File</th>
                <th className="py-3 pr-6">Date</th>
                <th className="py-3 pr-6">Status</th>
                <th className="py-3">CVSS</th>
              </tr>
            </thead>
            <tbody className="divide-y dark:divide-gray-700">
              <tr className="hover:bg-gray-50 dark:hover:bg-gray-800/60">
                <td className="py-3 pr-6">frontend-code.zip</td>
                <td className="py-3 pr-6">15 September 2023</td>
                <td className="py-3 pr-6">
                  <span className="text-green-500 dark:text-green-400">Completed</span>
                </td>
                <td className="py-3">
                  <span className="bg-red-600 text-white px-2 py-1 rounded text-xs">8.5</span>
                </td>
              </tr>
              <tr className="hover:bg-gray-50 dark:hover:bg-gray-800/60">
                <td className="py-3 pr-6">mobile-app.js</td>
                <td className="py-3 pr-6">12 July 2023</td>
                <td className="py-3 pr-6">
                  <span className="text-yellow-500 dark:text-yellow-400">Pending</span>
                </td>
                <td className="py-3">
                  <span className="bg-yellow-500 text-white px-2 py-1 rounded text-xs">5.4</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default SAST;
