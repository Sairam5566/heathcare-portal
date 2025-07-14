// API Configuration
const API_CONFIG = {
    BASE_URL: `${window.location.origin}/api`,
    ENDPOINTS: {
        SEND_REMINDER: '/reminders/send'
    }
};

// Helper function to get full API URL
function getApiUrl(endpoint) {
    return `${API_CONFIG.BASE_URL}${endpoint}`;
}
