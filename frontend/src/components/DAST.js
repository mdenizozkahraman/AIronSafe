import React, { useState, useEffect } from 'react';
import { HiOutlineSearch, HiOutlineExclamationCircle, HiOutlineInformationCircle, HiChevronDown, HiChevronUp, HiOutlineDownload, HiOutlineDocumentText, HiOutlineCode } from 'react-icons/hi';

const DAST = () => {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [error, setError] = useState('');
  const [expandedAlert, setExpandedAlert] = useState(null);
  const [filterKeyword, setFilterKeyword] = useState('');

  useEffect(() => {
    // Fetch scan history when component mounts
    fetchScanHistory();
  }, []);

  const fetchScanHistory = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/dast/scan_history');
      const data = await response.json();
      
      if (response.ok) {
        setScanHistory(data.history);
      } else {
        console.error('Failed to fetch scan history:', data.message);
      }
    } catch (err) {
      console.error('Error fetching scan history:', err);
    }
  };

  const handleUrlChange = (e) => {
    setUrl(e.target.value);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!url) return;
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      setError('Please enter a valid URL starting with http:// or https://');
      return;
    }

    setScanning(true);
    setError('');
    setScanResults(null);
    
    try {
      const response = await fetch('http://localhost:5000/api/dast/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        setScanResults(data.results);
        // Refresh scan history after new scan
        fetchScanHistory();
      } else {
        setError(data.message || 'Failed to start scan');
      }
    } catch (err) {
      console.error('Error starting scan:', err);
      setError('Failed to connect to scan service. Please try again later.');
    } finally {
      setScanning(false);
    }
  };

  const toggleAlert = (alertIndex) => {
    if (expandedAlert === alertIndex) {
      setExpandedAlert(null);
    } else {
      setExpandedAlert(alertIndex);
    }
  };

  const getRiskBadgeClass = (risk) => {
    switch (risk.toLowerCase()) {
      case 'high':
        return 'bg-red-600 text-white';
      case 'medium':
        return 'bg-yellow-500 text-white';
      case 'low':
        return 'bg-blue-500 text-white';
      case 'info':
        return 'bg-gray-500 text-white';
      default:
        return 'bg-gray-500 text-white';
    }
  };

  const filteredHistory = scanHistory.filter(scan => 
    scan.target_url.toLowerCase().includes(filterKeyword.toLowerCase())
  );

  // Download scan report with format option
  const downloadReport = async (scanId, format = 'pdf') => {
    try {
      setError('');
      
      if (format === 'pdf' || format === 'html') {
        // Direct browser download for PDF and HTML
        window.open(`http://localhost:5000/api/dast/report/${scanId}?format=${format}`, '_blank');
        return;
      }
      
      // For JSON format
      const response = await fetch(`http://localhost:5000/api/dast/report/${scanId}`);
      
      if (!response.ok) {
        throw new Error('Failed to download report');
      }
      
      const reportData = await response.json();
      const reportStr = JSON.stringify(reportData, null, 2);
      
      const blob = new Blob([reportStr], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = `scan_report_${scanId}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
    } catch (err) {
      console.error('Error downloading report:', err);
      setError('Failed to download report: ' + err.message);
    }
    };

    return (
    <div className="space-y-6">
      {error && (
        <div className="p-4 bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 rounded-lg flex items-center">
          <HiOutlineExclamationCircle className="h-5 w-5 mr-2" />
          {error}
        </div>
      )}

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

      {scanResults && (
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-lg font-semibold">Scan Results for {scanResults.target_url}</h2>
            <span className="text-sm text-gray-500 dark:text-gray-400">
              {scanResults.scan_date}
            </span>
          </div>
          
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg text-center">
              <span className="block text-2xl font-bold text-red-700 dark:text-red-400">{scanResults.summary.high_alerts}</span>
              <span className="text-sm text-gray-600 dark:text-gray-400">High Risk</span>
            </div>
            <div className="bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-lg text-center">
              <span className="block text-2xl font-bold text-yellow-700 dark:text-yellow-400">{scanResults.summary.medium_alerts}</span>
              <span className="text-sm text-gray-600 dark:text-gray-400">Medium Risk</span>
            </div>
            <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg text-center">
              <span className="block text-2xl font-bold text-blue-700 dark:text-blue-400">{scanResults.summary.low_alerts}</span>
              <span className="text-sm text-gray-600 dark:text-gray-400">Low Risk</span>
            </div>
            <div className="bg-gray-50 dark:bg-gray-700/30 p-4 rounded-lg text-center">
              <span className="block text-2xl font-bold text-gray-700 dark:text-gray-400">{scanResults.summary.info_alerts}</span>
              <span className="text-sm text-gray-600 dark:text-gray-400">Info</span>
                </div>
                </div>
          
          <h3 className="text-md font-semibold mb-3">Detected Vulnerabilities</h3>
          <div className="space-y-3">
            {scanResults.alerts.map((alert, index) => (
              <div 
                key={index} 
                className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden"
              >
                <div 
                  className="flex justify-between items-center p-3 bg-gray-50 dark:bg-gray-700 cursor-pointer"
                  onClick={() => toggleAlert(index)}
                >
                  <div className="flex items-center">
                    <span className={`px-2 py-1 rounded text-xs mr-3 ${getRiskBadgeClass(alert.risk)}`}>
                      {alert.risk}
                    </span>
                    <span className="font-medium">{alert.name}</span>
                  </div>
                  {expandedAlert === index ? <HiChevronUp className="h-5 w-5" /> : <HiChevronDown className="h-5 w-5" />}
                </div>

                {expandedAlert === index && (
                  <div className="p-3 bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <h4 className="text-sm font-semibold mb-1">Description</h4>
                        <p className="text-sm text-gray-600 dark:text-gray-400">{alert.description}</p>
                      </div>
                      <div>
                        <h4 className="text-sm font-semibold mb-1">URL</h4>
                        <p className="text-sm text-blue-600 dark:text-blue-400 break-all">{alert.url}</p>
                      </div>
                    </div>
                    <div className="mt-4">
                      <h4 className="text-sm font-semibold mb-1">Solution</h4>
                      <p className="text-sm text-gray-600 dark:text-gray-400">{alert.solution}</p>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-lg font-semibold">DAST Scan History</h2>
        </div>
        <div className="mb-4">
          <input 
            type="text" 
            placeholder="Search by URL..." 
            value={filterKeyword}
            onChange={(e) => setFilterKeyword(e.target.value)}
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
                <th className="py-3 pr-6">Risk Level</th>
                <th className="py-3 text-center">Reports</th>
              </tr>
            </thead>
            <tbody className="divide-y dark:divide-gray-700">
              {filteredHistory.length > 0 ? (
                filteredHistory.map((scan, index) => (
                  <tr key={index} className="hover:bg-gray-50 dark:hover:bg-gray-800/60">
                    <td className="py-3 pr-6">{scan.target_url}</td>
                    <td className="py-3 pr-6">{scan.scan_date}</td>
                    <td className="py-3 pr-6">
                      <span className={`text-${scan.status === 'completed' ? 'green' : 'red'}-500 dark:text-${scan.status === 'completed' ? 'green' : 'red'}-400`}>
                        {scan.status === 'completed' ? 'Completed' : 'Failed'}
                      </span>
                    </td>
                    <td className="py-3 pr-6">
                      {scan.status === 'completed' ? (
                        <span className={`bg-${scan.high_alerts > 0 ? 'red' : scan.medium_alerts > 0 ? 'yellow' : 'blue'}-600 text-white px-2 py-1 rounded text-xs`}>
                          {scan.high_alerts > 0 ? scan.high_alerts : scan.medium_alerts > 0 ? scan.medium_alerts : scan.low_alerts}
                        </span>
                      ) : (
                        <span className="bg-gray-600 text-white px-2 py-1 rounded text-xs">—</span>
                      )}
                    </td>
                    <td className="py-3 text-center">
                      {scan.status === 'completed' && (
                        <div className="flex justify-center space-x-2">
                          <button
                            onClick={() => downloadReport(scan.scan_id, 'pdf')}
                            className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 transition-colors"
                            title="Download PDF Report"
                          >
                            <HiOutlineDocumentText className="h-5 w-5" />
                          </button>
                          <button
                            onClick={() => downloadReport(scan.scan_id, 'html')}
                            className="text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-300 transition-colors"
                            title="Download HTML Report"
                          >
                            <HiOutlineCode className="h-5 w-5" />
                          </button>
                          <button
                            onClick={() => downloadReport(scan.scan_id, 'json')}
                            className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 transition-colors"
                            title="Download JSON Report"
                          >
                            <HiOutlineDownload className="h-5 w-5" />
                    </button>
                </div>
                      )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="5" className="py-4 text-center text-gray-500 dark:text-gray-400">
                    No scan history found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
        </div>
    );
};

export default DAST;
