window.API = {
    courseId: null,
    learnerId: 'user123', // In production, get from auth
    
    initialize: function(courseId) {
        this.courseId = courseId;
    },
    
    LMSInitialize: function(param) {
        return this._call('LMSInitialize');
    },
    
    LMSFinish: function(param) {
        return this._call('LMSFinish');
    },
    
    LMSGetValue: function(element) {
        const result = this._call('LMSGetValue', element);
        return result.result;
    },
    
    LMSSetValue: function(element, value) {
        const result = this._call('LMSSetValue', element, value);
        return result.result;
    },
    
    LMSCommit: function(param) {
        return this._call('LMSCommit');
    },
    
    LMSGetLastError: function() {
        return "0";
    },
    
    LMSGetErrorString: function(errorCode) {
        const errors = {
            "0": "No error",
            "201": "Invalid argument"
        };
        return errors[errorCode] || "Unknown error";
    },
    
    LMSGetDiagnostic: function(errorCode) {
        return this.LMSGetErrorString(errorCode);
    },
    
    _call: function(action, element, value) {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', `/api/scorm/${this.courseId}/${this.learnerId}`, false);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(JSON.stringify({ action, element, value }));
        
        if (xhr.status === 200) {
            const response = JSON.parse(xhr.responseText);
            return response;
        }
        return { result: 'false', error: '301' };
    }
};