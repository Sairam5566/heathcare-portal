class ReminderService {
    static async sendReminder(phoneNumber, message) {
    try {
        const response = await fetch(getApiUrl(API_CONFIG.ENDPOINTS.SEND_REMINDER), {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                PhoneNumber: phoneNumber,
                Message: message
            }),
            credentials: 'include' // Include cookies for authentication if needed
        });

        if (!response.ok) {
            let errMsg = 'Failed to send reminder';
            try {
                const errorObj = await response.json();
                errMsg = errorObj.message || JSON.stringify(errorObj) || errMsg;
            } catch {
                try {
                    errMsg = await response.text() || errMsg;
                } catch {}
            }
            // Always throw an Error with a message property
            const error = new Error(errMsg);
            error.message = errMsg;
            throw error;
        }

        try {
            return await response.json();
        } catch {
            return { raw: await response.text() };
        }
    } catch (error) {
        let msg = error && error.message ? error.message : 'Unknown error sending reminder';
        console.error('Error sending reminder:', msg);
        if (!error.message) error.message = msg;
        throw error;
    }
}
}

// Usage example:
// try {
//     const result = await ReminderService.sendReminder('+1234567890', 'Your appointment is scheduled for tomorrow at 10 AM');
//     console.log('Reminder sent:', result);
// } catch (error) {
//     console.error('Failed to send reminder:', error);
// }
