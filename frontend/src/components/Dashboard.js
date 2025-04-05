import React from 'react';

const Dashboard = () => {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md flex flex-col items-center">
          <span className="text-2xl font-bold text-blue-600 dark:text-blue-400 mb-2">24</span>
          <span className="text-gray-600 dark:text-gray-400">Total Scans</span>
        </div>
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md flex flex-col items-center">
          <span className="text-2xl font-bold text-red-600 dark:text-red-400 mb-2">5</span>
          <span className="text-gray-600 dark:text-gray-400">Critical Issues</span>
        </div>
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md flex flex-col items-center">
          <span className="text-2xl font-bold text-green-600 dark:text-green-400 mb-2">12</span>
          <span className="text-gray-600 dark:text-gray-400">Resolved Issues</span>
        </div>
      </div>
      
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
        <h2 className="text-lg font-semibold mb-4">Recent Activity</h2>
        <div className="space-y-2">
          <div className="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
            <p className="text-sm">SAST scan completed for frontend-code.zip</p>
            <p className="text-xs text-gray-500 dark:text-gray-400">Today, 10:30 AM</p>
          </div>
          <div className="p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
            <p className="text-sm">DAST scan started for https://example.com</p>
            <p className="text-xs text-gray-500 dark:text-gray-400">Yesterday, 3:45 PM</p>
          </div>
        </div>
      </div>
      
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
        <h2 className="text-lg font-semibold mb-4">Scan History</h2>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left border-b border-gray-200 dark:border-gray-700">
              <th className="py-2">Type</th>
              <th className="py-2">Target</th>
              <th className="py-2">Date</th>
              <th className="py-2">Status</th>
            </tr>
          </thead>
          <tbody>
            <tr className="border-b border-gray-100 dark:border-gray-800">
              <td className="py-2">SAST</td>
              <td className="py-2">frontend-code.zip</td>
              <td className="py-2">15 Eyl 2023</td>
              <td className="py-2"><span className="bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400 px-2 py-1 rounded text-xs">Completed</span></td>
            </tr>
            <tr>
              <td className="py-2">DAST</td>
              <td className="py-2">https://example.com</td>
              <td className="py-2">14 Eyl 2023</td>
              <td className="py-2"><span className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400 px-2 py-1 rounded text-xs">In Progress</span></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Dashboard;
