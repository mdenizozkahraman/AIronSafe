import React, { useState, useEffect } from 'react';

const Dashboard = () => {
  const [sastHistory, setSastHistory] = useState([]);
  const [dastHistory, setDastHistory] = useState([]);
  const [totalScans, setTotalScans] = useState(0);
  const [sastCriticalIssues, setSastCriticalIssues] = useState(0);
  const [dastCriticalIssues, setDastCriticalIssues] = useState(0);
  const [sastMediumIssues, setSastMediumIssues] = useState(0);
  const [dastMediumIssues, setDastMediumIssues] = useState(0);
  const [sastLowIssues, setSastLowIssues] = useState(0);
  const [dastLowIssues, setDastLowIssues] = useState(0);
  const [chartInstance, setChartInstance] = useState(null);
  const [showSAST, setShowSAST] = useState(true);
  const [showDAST, setShowDAST] = useState(true);

  useEffect(() => {
    // Load Chart.js from CDN
    const script = document.createElement('script');
    script.src = 'https://cdn.jsdelivr.net/npm/chart.js';
    script.async = true;
    script.onload = () => {
      // Fetch data after Chart.js is loaded
      fetchScanHistories();
    };
    document.body.appendChild(script);

    return () => {
      // Cleanup
      if (chartInstance) {
        chartInstance.destroy();
      }
      document.body.removeChild(script);
    };
  }, []);

  // Add effect to update chart when visibility toggles change
  useEffect(() => {
    const canvas = document.getElementById('findingsChart');
    if (canvas && sastHistory.length > 0) {
      createChart(canvas, sastHistory, dastHistory);
    }
  }, [showSAST, showDAST]);

  const createChart = (canvasElement, sastHistory, dastHistory) => {
    if (!canvasElement || !window.Chart) return;

    // Destroy existing chart if any
    if (chartInstance) {
      chartInstance.destroy();
    }

    // Format date to show only day and parse date function
    const formatDate = (dateString) => {
      const date = new Date(dateString);
      return date.toLocaleDateString('tr-TR', { 
        day: '2-digit',
        month: '2-digit',
        year: 'numeric'
      });
    };

    const parseDate = (dateString) => {
      const [day, month, year] = dateString.split('.');
      return new Date(year, month - 1, day);
    };

    // Prepare data
    const allScans = [
      ...(showSAST ? sastHistory.map(scan => ({
        date: formatDate(scan.scan_date),
        originalDate: scan.scan_date,
        total: (scan.summary?.high || 0) + (scan.summary?.medium || 0) + (scan.summary?.low || 0),
        type: 'SAST'
      })) : []),
      ...(showDAST ? dastHistory.map(scan => ({
        date: formatDate(scan.scan_date),
        originalDate: scan.scan_date,
        total: (scan.alerts_count?.high || scan.high_alerts || 0) +
               (scan.alerts_count?.medium || scan.medium_alerts || 0) +
               (scan.alerts_count?.low || scan.low_alerts || 0),
        type: 'DAST'
      })) : [])
    ];

    // Get unique dates and sort them chronologically
    const uniqueDates = [...new Set(allScans.map(scan => scan.date))]
      .sort((a, b) => parseDate(a) - parseDate(b));

    // Prepare datasets
    const datasets = [];
    
    if (showSAST) {
      const sastData = uniqueDates.map(date => {
        const scan = allScans.find(s => s.date === date && s.type === 'SAST');
        return scan ? scan.total : 0;
      });
      datasets.push({
        label: 'SAST Findings',
        data: sastData,
        backgroundColor: 'rgba(255, 99, 132, 0.7)',
        borderColor: 'rgba(255, 99, 132, 1)',
        borderWidth: 1,
        borderRadius: 4,
        barPercentage: 0.8,
        categoryPercentage: 0.4
      });
    }

    if (showDAST) {
      const dastData = uniqueDates.map(date => {
        const scan = allScans.find(s => s.date === date && s.type === 'DAST');
        return scan ? scan.total : 0;
      });
      datasets.push({
        label: 'DAST Findings',
        data: dastData,
        backgroundColor: 'rgba(54, 162, 235, 0.7)',
        borderColor: 'rgba(54, 162, 235, 1)',
        borderWidth: 1,
        borderRadius: 4,
        barPercentage: 0.8,
        categoryPercentage: 0.4
      });
    }

    // Create new chart
    const newChart = new window.Chart(canvasElement, {
      type: 'bar',
      data: {
        labels: uniqueDates,
        datasets: datasets
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'top',
            labels: {
              usePointStyle: true,
              padding: 20
            }
          },
          title: {
            display: true,
            text: 'Daily Total Findings',
            font: {
              size: 16,
              weight: 'bold'
            },
            padding: {
              top: 10,
              bottom: 20
            }
          },
          tooltip: {
            callbacks: {
              title: (tooltipItems) => {
                return `Date: ${tooltipItems[0].label}`;
              },
              label: (context) => {
                return `${context.dataset.label}: ${context.parsed.y} findings`;
              }
            }
          }
        },
        scales: {
          x: {
            grid: {
              display: false
            },
            title: {
              display: true,
              text: 'Scan Date',
              padding: {
                top: 10
              }
            }
          },
          y: {
            beginAtZero: true,
            title: {
              display: true,
              text: 'Number of Findings',
              padding: {
                bottom: 10
              }
            },
            grid: {
              color: 'rgba(0, 0, 0, 0.1)',
              drawBorder: false
            }
          }
        }
      }
    });

    setChartInstance(newChart);
  };

  const fetchScanHistories = async () => {
    try {
      // Fetch SAST history
      const sastResponse = await fetch('https://aironsafe.com/api/sast/scan_history');
      const sastData = await sastResponse.json();
      
      // Fetch DAST history
      const dastResponse = await fetch('https://aironsafe.com/api/dast/scan_history');
      const dastData = await dastResponse.json();
      
      if (sastResponse.ok && dastResponse.ok) {
        const sastHistory = sastData.history || [];
        const dastHistory = dastData.history || [];
        
        setSastHistory(sastHistory);
        setDastHistory(dastHistory);
        setTotalScans(sastHistory.length + dastHistory.length);

        // Calculate issues from SAST scans
        const sastCritical = sastHistory.reduce((total, scan) => {
          return total + (scan.summary?.high || 0);
        }, 0);
        const sastMedium = sastHistory.reduce((total, scan) => {
          return total + (scan.summary?.medium || 0);
        }, 0);
        const sastLow = sastHistory.reduce((total, scan) => {
          return total + (scan.summary?.low || 0);
        }, 0);
        setSastCriticalIssues(sastCritical);
        setSastMediumIssues(sastMedium);
        setSastLowIssues(sastLow);

        // Calculate issues from DAST scans
        const dastCritical = dastHistory.reduce((total, scan) => {
          return total + (scan.alerts_count?.high || scan.high_alerts || 0);
        }, 0);
        const dastMedium = dastHistory.reduce((total, scan) => {
          return total + (scan.alerts_count?.medium || scan.medium_alerts || 0);
        }, 0);
        const dastLow = dastHistory.reduce((total, scan) => {
          return total + (scan.alerts_count?.low || scan.low_alerts || 0);
        }, 0);
        setDastCriticalIssues(dastCritical);
        setDastMediumIssues(dastMedium);
        setDastLowIssues(dastLow);

        // Create chart after data is loaded
        const canvas = document.getElementById('findingsChart');
        if (canvas) {
          createChart(canvas, sastHistory, dastHistory);
        }
      }
    } catch (err) {
      console.error('Error fetching scan histories:', err);
    }
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md flex flex-col items-center">
          <span className="text-2xl font-bold text-blue-600 dark:text-blue-400 mb-2">{totalScans}</span>
          <div className="text-center">
            <span className="text-gray-600 dark:text-gray-400">Total Scans</span>
            <div className="text-sm text-gray-500 dark:text-gray-500 mt-1">
              (SAST: {sastHistory.length}, DAST: {dastHistory.length})
            </div>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md flex flex-col items-center">
          <span className="text-2xl font-bold text-red-600 dark:text-red-400 mb-2">{sastCriticalIssues + dastCriticalIssues}</span>
          <div className="text-center">
            <span className="text-gray-600 dark:text-gray-400">Critical Issues</span>
            <div className="text-sm text-gray-500 dark:text-gray-500 mt-1">
              (SAST: {sastCriticalIssues}, DAST: {dastCriticalIssues})
            </div>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md flex flex-col items-center">
          <span className="text-2xl font-bold text-yellow-600 dark:text-yellow-400 mb-2">{sastMediumIssues + dastMediumIssues}</span>
          <div className="text-center">
            <span className="text-gray-600 dark:text-gray-400">Medium Issues</span>
            <div className="text-sm text-gray-500 dark:text-gray-500 mt-1">
              (SAST: {sastMediumIssues}, DAST: {dastMediumIssues})
            </div>
          </div>
        </div>
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md flex flex-col items-center">
          <span className="text-2xl font-bold text-blue-600 dark:text-blue-400 mb-2">{sastLowIssues + dastLowIssues}</span>
          <div className="text-center">
            <span className="text-gray-600 dark:text-gray-400">Low Issues</span>
            <div className="text-sm text-gray-500 dark:text-gray-500 mt-1">
              (SAST: {sastLowIssues}, DAST: {dastLowIssues})
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-md">
        <div className="flex items-center justify-end space-x-6 mb-4">
          <label className="inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={showSAST}
              onChange={(e) => setShowSAST(e.target.checked)}
              className="form-checkbox h-5 w-5 text-red-600 rounded border-gray-300 focus:ring-red-500 dark:border-gray-600 dark:bg-gray-700"
            />
            <span className="ml-2 text-gray-700 dark:text-gray-300">Show SAST</span>
          </label>
          <label className="inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={showDAST}
              onChange={(e) => setShowDAST(e.target.checked)}
              className="form-checkbox h-5 w-5 text-blue-600 rounded border-gray-300 focus:ring-blue-500 dark:border-gray-600 dark:bg-gray-700"
            />
            <span className="ml-2 text-gray-700 dark:text-gray-300">Show DAST</span>
          </label>
        </div>
        <div className="h-80">
          <canvas id="findingsChart"></canvas>
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
              <td className="py-2">15 September 2023</td>
              <td className="py-2"><span className="bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400 px-2 py-1 rounded text-xs">Completed</span></td>
            </tr>
            <tr>
              <td className="py-2">DAST</td>
              <td className="py-2">https://example.com</td>
              <td className="py-2">14 August 2023</td>
              <td className="py-2"><span className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400 px-2 py-1 rounded text-xs">In Progress</span></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Dashboard;
