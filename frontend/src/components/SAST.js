import React from 'react';
import { commonStyles } from '../styles/commonStyles';

const SAST = () => {
    const uploadFile = () => {
        alert('File uploaded successfully!');
    };

    return (
        <div style={commonStyles.container}>
            <header style={commonStyles.header}>
                AIronSafe SAST
            </header>

            <nav style={commonStyles.nav}>
                <div>
                    <a href="/dashboard" style={commonStyles.link}>Dashboard</a>
                    <a href="/sast" style={commonStyles.link}>SAST</a>
                    <a href="/dast" style={commonStyles.link}>DAST</a>
                </div>
                <div>
                    <a href="/" style={commonStyles.link}>Logout</a>
                </div>
            </nav>

            <div style={commonStyles.content}>
                <div style={commonStyles.sidebar}>
                    <h3 style={commonStyles.sidebarTitle}>Previous Reports</h3>
                    <ul style={commonStyles.list}>
                        <li style={commonStyles.listItem}>Report_01.pdf</li>
                        <li style={commonStyles.listItem}>Report_02.pdf</li>
                        <li style={commonStyles.listItem}>Report_03.pdf</li>
                    </ul>
                </div>

                <div style={commonStyles.main}>
                    <input type="file" />
                    <button onClick={uploadFile} style={commonStyles.button}>
                        Upload and Scan
                    </button>
                </div>
            </div>
        </div>
    );
};

export default SAST;
