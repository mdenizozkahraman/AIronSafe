export const commonStyles = {
    container: {
        fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
        backgroundColor: '#f9fafc',
        height: '100vh',
        color: '#333',
        display: 'flex',
        flexDirection: 'column',
    },
    header: {
        backgroundColor: '#ffffff',
        padding: '1rem',
        textAlign: 'center',
        fontSize: '2rem',
        fontWeight: 'bold',
        color: '#4CAF50',
        position: 'fixed',
        top: 0,
        width: '100%',
        zIndex: 10,
        borderBottom: '1px solid #ddd',
    },
    nav: {
        backgroundColor: '#ffffff',
        padding: '1rem',
        display: 'flex',
        justifyContent: 'space-between',
        position: 'fixed',
        top: '4rem',
        width: '100%',
        zIndex: 9,
        borderBottom: '1px solid #ddd',
    },
    link: {
        color: '#333',
        textDecoration: 'none',
        fontSize: '1rem',
        margin: '0 1rem',
        cursor: 'pointer',
    },
    content: {
        display: 'flex',
        marginTop: '8rem', // Leave space equivalent to Header + Navbar height
        height: 'calc(100vh - 8rem)',
        width: '100vw', // Cover the full width
    },
    sidebar: {
        width: '18%', // Keep sidebar width fixed
        backgroundColor: '#f9f9f9',
        padding: '1.5rem',
        borderRight: '1px solid #ddd',
        overflowY: 'auto',
        boxSizing: 'border-box',
    },
    main: {
        flexGrow: 1, // Fill all remaining space
        width: '82%', // Width proportional to sidebar
        padding: '2rem',
        backgroundColor: '#ffffff',
        overflowY: 'auto',
        boxSizing: 'border-box',
    },
    stats: {
        display: 'flex',
        justifyContent: 'space-between',
        gap: '1rem',
    },
    card: {
        flex: 1,
        backgroundColor: '#ffffff',
        border: '1px solid #ddd',
        padding: '1.5rem',
        borderRadius: '8px',
        textAlign: 'center',
        boxShadow: '0 2px 5px rgba(0,0,0,0.05)',
        fontSize: '1rem',
    },
    button: {
        width: '100%',
        padding: '1rem',
        backgroundColor: '#4CAF50',
        color: '#ffffff',
        border: 'none',
        borderRadius: '8px',
        fontSize: '1rem',
        cursor: 'pointer',
        transition: 'background-color 0.2s',
    },
};
