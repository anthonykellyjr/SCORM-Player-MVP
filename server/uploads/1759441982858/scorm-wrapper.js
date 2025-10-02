// SCORM API wrapper for Storyline HTML5 output
// This ensures the course can find the SCORM API

// Storyline looks for the API in the parent window
if (window.parent && window.parent.API) {
    window.API = window.parent.API;
} else if (window.top && window.top.API) {
    window.API = window.top.API;
} else {
    // If no API found, create a mock one for testing
    console.warn('No SCORM API found, creating mock API');
    window.API = {
        LMSInitialize: function() { return "true"; },
        LMSFinish: function() { return "true"; },
        LMSGetValue: function(key) { return ""; },
        LMSSetValue: function(key, value) { return "true"; },
        LMSCommit: function() { return "true"; },
        LMSGetLastError: function() { return "0"; },
        LMSGetErrorString: function(errorCode) { return "No error"; },
        LMSGetDiagnostic: function(errorCode) { return "No error"; }
    };
}

// Initialize SCORM on page load
window.addEventListener('load', function() {
    if (window.API && window.API.LMSInitialize) {
        window.API.LMSInitialize('');
        console.log('SCORM initialized');
    }
});

// Finish SCORM on page unload
window.addEventListener('beforeunload', function() {
    if (window.API && window.API.LMSFinish) {
        window.API.LMSFinish('');
        console.log('SCORM finished');
    }
});