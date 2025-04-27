import React, { useState, useEffect } from 'react';
import { HiOutlineUpload, HiOutlineExclamationCircle, HiOutlineInformationCircle, HiChevronDown, HiChevronUp, HiOutlineDownload, HiOutlineDocumentText } from 'react-icons/hi';

const SAST = () => {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [error, setError] = useState('');
  const [expandedVulnerability, setExpandedVulnerability] = useState(null);
  const [filterKeyword, setFilterKeyword] = useState('');
  const [isDragging, setIsDragging] = useState(false);

  // Fetch scan history when component mounts
  useEffect(() => {
    fetchScanHistory();
  }, []);

  const fetchScanHistory = async () => {
    try {
      const response = await fetch('https://aironsafe.com/api/sast/scan_history');
      const data = await response.json();
      
      if (response.ok) {
        setScanHistory(data.history);
      } else {
        console.error('Failed to fetch scan history:', data.message);
        setError('Failed to fetch scan history');
      }
    } catch (err) {
      console.error('Error fetching scan history:', err);
      setError('Error connecting to server');
    }
  };

  const handleFileChange = (e) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      setFile(selectedFile);
      setScanResults(null);
      setError('');
    }
  };

  const handleDragEnter = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    
    const droppedFile = e.dataTransfer.files?.[0];
    if (droppedFile) {
      setFile(droppedFile);
      setScanResults(null);
      setError('');
    }
  };

  const handleFileUpload = async (e) => {
    e.preventDefault();
    if (!file) return;

    setUploading(true);
    setError('');
    setScanResults(null);
    
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const response = await fetch('https://aironsafe.com/api/sast/scan', {
        method: 'POST',
        body: formData
      });
      
      const data = await response.json();
      
      if (response.ok) {
        setScanResults(data.results);
        // Refresh scan history after successful scan
        fetchScanHistory();
      } else {
        setError(data.message || 'Failed to analyze file');
      }
    } catch (err) {
      console.error('Error uploading file:', err);
      setError('Error connecting to server');
    } finally {
      setUploading(false);
      setFile(null);
    }
  };

  const toggleVulnerability = (id) => {
    setExpandedVulnerability(expandedVulnerability === id ? null : id);
  };

  const downloadReport = async (scanId, format = 'json') => {
    try {
      setError('');
      
      if (format === 'pdf' || format === 'html') {
        // For PDF and HTML, open in a new tab to trigger browser download
        window.open(`https://aironsafe.com/api/sast/report/${scanId}?format=${format}`, '_blank');
        return;
      }
      
      // For JSON format
      const response = await fetch(`https://aironsafe.com/api/sast/report/${scanId}`);
      
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
      a.download = `sast_report_${scanId}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
    } catch (err) {
      console.error('Error downloading report:', err);
      setError('Failed to download report: ' + err.message);
    }
  };

  // Get appropriate color classes based on severity
  const getSeverityClass = (severity) => {
    switch (severity) {
      case 'high':
        return 'bg-red-600 text-white';
      case 'medium':
        return 'bg-yellow-500 text-white';
      case 'low':
        return 'bg-blue-500 text-white';
      default:
        return 'bg-gray-500 text-white';
    }
  };

  // Filter scan history based on search term
  const filteredHistory = scanHistory.filter(scan => 
    scan.filename.toLowerCase().includes(filterKeyword.toLowerCase())
  );

    return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
        <h2 className="text-lg font-semibold mb-4">Upload Code for Analysis</h2>
        <form onSubmit={handleFileUpload} className="space-y-4">
          <div className="flex items-center justify-center w-full">
            <label 
              className={`flex flex-col items-center justify-center w-full h-48 border-2 border-dashed rounded-lg cursor-pointer transition-all duration-200 ${
                isDragging 
                  ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/30' 
                  : file 
                    ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20' 
                    : 'border-gray-300 dark:border-gray-600 hover:bg-gray-100 dark:hover:bg-gray-700/30'
              }`}
              onDragEnter={handleDragEnter}
              onDragLeave={handleDragLeave}
              onDragOver={handleDragOver}
              onDrop={handleDrop}
            >
              <div className="flex flex-col items-center justify-center pt-5 pb-6">
                <HiOutlineUpload className={`w-10 h-10 mb-3 ${file || isDragging ? 'text-blue-600 dark:text-blue-400' : 'text-gray-500 dark:text-gray-400'}`} />
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

      {/* Error Message */}
      {error && (
        <div className="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 rounded dark:bg-red-900/20 dark:text-red-400 dark:border-red-800">
          <div className="flex items-center">
            <HiOutlineExclamationCircle className="h-5 w-5 mr-2" />
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* Scan Results */}
      {scanResults && (
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
          <h2 className="text-lg font-semibold mb-4">Scan Results</h2>
          
          <div className="mb-6 grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-red-100 dark:bg-red-900/20 p-4 rounded-lg text-center">
              <span className="block text-3xl font-bold text-red-600 dark:text-red-400">
                {scanResults.summary.high}
              </span>
            </div>
            <div className="bg-yellow-100 dark:bg-yellow-900/20 p-4 rounded-lg text-center">
              <span className="block text-3xl font-bold text-yellow-600 dark:text-yellow-400">
                {scanResults.summary.medium}
              </span>
            </div>
            <div className="bg-blue-100 dark:bg-blue-900/20 p-4 rounded-lg text-center">
              <span className="block text-3xl font-bold text-blue-600 dark:text-blue-400">
                {scanResults.summary.low}
              </span>
            </div>
          </div>
          
          <h3 className="font-medium text-gray-700 dark:text-gray-300 mb-2">
            Vulnerabilities ({scanResults.vulnerabilities.length})
          </h3>
          
          <div className="space-y-3">
            {scanResults.no_vulnerabilities_found ? (
              <div className="p-4 bg-green-100 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg text-center">
                <p className="text-green-600 dark:text-green-400 font-medium">
                  No vulnerabilities were detected in the uploaded code. Great job!
                </p>
              </div>
            ) : (
              scanResults.vulnerabilities.map((vuln) => (
                <div 
                  key={vuln.id} 
                  className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden"
                >
                  <div 
                    className="p-3 flex justify-between items-center cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800/60"
                    onClick={() => toggleVulnerability(vuln.id)}
                  >
                    <div className="flex items-center">
                      <span className={`px-2 py-1 rounded-md text-xs mr-3 ${getSeverityClass(vuln.severity)}`}>
                        {vuln.severity.toUpperCase()}
                      </span>
                      <span className="font-medium">{vuln.name}</span>
                    </div>
                    {expandedVulnerability === vuln.id ? (
                      <HiChevronUp className="h-5 w-5 text-gray-500" />
                    ) : (
                      <HiChevronDown className="h-5 w-5 text-gray-500" />
                    )}
                  </div>
                  
                  {expandedVulnerability === vuln.id && (
                    <div className="p-4 bg-gray-50 dark:bg-gray-800/40 border-t border-gray-200 dark:border-gray-700">
                      <p className="text-gray-700 dark:text-gray-300 mb-2">
                        <span className="font-medium">Description:</span> {vuln.description}
                      </p>
                      <p className="text-gray-700 dark:text-gray-300 mb-2">
                        <span className="font-medium">File:</span> {vuln.file}
                      </p>
                      <p className="text-gray-700 dark:text-gray-300 mb-2">
                        <span className="font-medium">Line:</span> {vuln.line}
                      </p>
                      <p className="text-gray-700 dark:text-gray-300 mb-2">
                        <span className="font-medium">CVSS:</span> {vuln.cvss}
                      </p>
                      <div className="mt-3 mb-3 bg-gray-100 dark:bg-gray-700 p-2 rounded-md overflow-x-auto">
                        <pre className="text-sm text-gray-800 dark:text-gray-300 font-mono">
                          {vuln.code_snippet}
                        </pre>
                      </div>
                      <div className="text-gray-700 dark:text-gray-300">
                        <span className="font-medium">AI Recommendation:</span> 
                        <div dangerouslySetInnerHTML={{ __html: vuln.recommendation }} />
                      </div>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      )}

      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
        <div className="flex justify-between items-center mb-4">
          <div className="flex items-center space-x-2">
            <h2 className="text-lg font-semibold">SAST Scan History</h2>
            <span className="px-2 py-1 text-sm bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 rounded-full">
              {filteredHistory.length} {filteredHistory.length === 1 ? 'entry' : 'entries'}
            </span>
          </div>
        </div>
        <div className="mb-4">
          <input 
            type="text" 
            placeholder="Search by file name..." 
            className="w-full p-2 rounded bg-gray-100 dark:bg-gray-700 border border-gray-200 dark:border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={filterKeyword}
            onChange={(e) => setFilterKeyword(e.target.value)}
          />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-gray-200 dark:border-gray-700">
                <th className="py-3 pr-6">File</th>
                <th className="py-3 pr-6">Date</th>
                <th className="py-3 pr-6">Status</th>
                <th className="py-3 pr-6">Risk Level</th>
                <th className="py-3">Reports</th>
              </tr>
            </thead>
            <tbody className="divide-y dark:divide-gray-700">
              {filteredHistory.map((scan) => (
                <tr key={scan.scan_id} className="hover:bg-gray-50 dark:hover:bg-gray-800/60">
                  <td className="py-3 pr-6">{scan.filename}</td>
                  <td className="py-3 pr-6">{scan.scan_date}</td>
                  <td className="py-3 pr-6">
                    <span className="text-green-500 dark:text-green-400">{scan.status}</span>
                  </td>
                  <td className="py-3 pr-6">
                    {scan.summary && (
                      <div className="flex space-x-2">
                        <span className="inline-flex items-center justify-center px-2 py-1 text-xs font-bold leading-none text-white bg-red-600 rounded">{scan.summary.high}</span>
                        <span className="inline-flex items-center justify-center px-2 py-1 text-xs font-bold leading-none text-white bg-yellow-500 rounded">{scan.summary.medium}</span>
                        <span className="inline-flex items-center justify-center px-2 py-1 text-xs font-bold leading-none text-white bg-blue-500 rounded">{scan.summary.low}</span>
                      </div>
                    )}
                  </td>
                  <td className="py-3">
                    <div className="flex space-x-2">
                      <button 
                        onClick={() => downloadReport(scan.scan_id, 'pdf')}
                        className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 p-1 rounded"
                        title="Download PDF Report"
                      >
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                        </svg>
                      </button>
                      <button 
                        onClick={() => downloadReport(scan.scan_id, 'html')}
                        className="text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-300 p-1 rounded"
                        title="Download HTML Report"
                      >
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                        </svg>
                      </button>
                      <button 
                        onClick={() => downloadReport(scan.scan_id, 'json')}
                        className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 p-1 rounded"
                        title="Download JSON Report"
                      >
                        <HiOutlineDownload className="h-5 w-5" />
                    </button>
                </div>
                  </td>
                </tr>
              ))}

              {filteredHistory.length === 0 && (
                <tr>
                  <td colSpan="6" className="py-4 text-center text-gray-500 dark:text-gray-400">
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

export default SAST;
