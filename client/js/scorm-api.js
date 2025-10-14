// Authentication-aware SCORM API with session tracking
(function() {
    const API_ENDPOINT = window.location.hostname === 'localhost' 
        ? 'http://localhost:3000' 
        : 'https://dev.orthoskool.com';
    
    // Generate unique session ID
    const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    // Get course and user info from PARENT window URL (since SCORM content loads in iframe)
    let urlParams;
    try {
        // Try to get params from parent window first
        urlParams = new URLSearchParams(window.parent.location.search);
    } catch (e) {
        // If can't access parent (cross-origin), try own window
        urlParams = new URLSearchParams(window.location.search);
    }
    
    const courseId = urlParams.get('courseId');
    const userId = urlParams.get('userId');
    
    // Get auth token from localStorage
    const getToken = () => localStorage.getItem('token');
    
    // Heartbeat to track active session
    let heartbeatInterval = null;
    
    function startHeartbeat() {
        console.log('Starting session heartbeat...');
        
        // Send immediate heartbeat on start
        sendHeartbeat();
        
        // Send heartbeat every 30 seconds
        heartbeatInterval = setInterval(() => {
            sendHeartbeat();
        }, 30000); // 30 seconds
    }
    
    function sendHeartbeat() {
        const token = getToken();
        if (!token) {
            console.warn('No auth token available for heartbeat');
            return;
        }
        
        fetch(`${API_ENDPOINT}/api/sessions/heartbeat`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                sessionId,
                courseId,
                userId
            })
        })
        .then(res => {
            if (!res.ok) {
                console.error('Heartbeat failed:', res.status);
            }
            return res.json();
        })
        .then(data => {
            console.log('Heartbeat sent:', data);
        })
        .catch(err => console.error('Heartbeat error:', err));
    }
    
    function stopHeartbeat() {
        if (heartbeatInterval) {
            clearInterval(heartbeatInterval);
            heartbeatInterval = null;
            console.log('Heartbeat stopped');
        }
    }
    
    // Helper function to send data to backend WITH AUTH
    function sendToBackend(action, element, value) {
        const token = getToken();
        if (!token) {
            console.error('No auth token available');
            return Promise.reject('No authentication');
        }
        
        return fetch(`${API_ENDPOINT}/api/scorm/${courseId}/${userId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                action,
                element,
                value,
                sessionId
            })
        })
        .then(res => {
            if (res.status === 401 || res.status === 403) {
                console.error('Authentication failed - redirecting to login');
                // Optional: redirect to login
                // window.location.href = '/login.html';
                throw new Error('Authentication failed');
            }
            return res.json();
        })
        .catch(err => {
            console.error('Backend communication error:', err);
            throw err;
        });
    }
    
    // SCORM API Implementation
    window.API = {
        _initialized: false,
        _finished: false,
        _errorCode: '0',
        _errorString: '',
        _lastError: '0',
        
        // SCORM 1.2 API Methods
        LMSInitialize: function(parameter) {
            console.log('LMSInitialize called');
            
            if (parameter !== '') {
                this._errorCode = '201';
                this._errorString = 'Invalid argument';
                return 'false';
            }
            
            if (this._initialized) {
                this._errorCode = '101';
                this._errorString = 'Already initialized';
                return 'false';
            }
            
            this._initialized = true;
            this._errorCode = '0';
            
            // Start session tracking
            startHeartbeat();
            
            // Notify backend of initialization
            sendToBackend('Initialize', null, null)
                .then(() => console.log('✓ SCORM session initialized'))
                .catch(err => console.error('✗ Failed to initialize session:', err));
            
            console.log('SCORM API Initialized', { courseId, userId, sessionId });
            return 'true';
        },
        
        LMSFinish: function(parameter) {
            console.log('LMSFinish called');
            
            if (parameter !== '') {
                this._errorCode = '201';
                return 'false';
            }
            
            if (!this._initialized) {
                this._errorCode = '301';
                return 'false';
            }
            
            if (this._finished) {
                this._errorCode = '101';
                return 'false';
            }
            
            this._finished = true;
            this._errorCode = '0';
            
            // Stop session tracking
            stopHeartbeat();
            
            // Commit any pending data
            this.LMSCommit('');
            
            // Notify backend of termination
            sendToBackend('Terminate', null, null)
                .then(() => console.log('✓ SCORM session terminated'))
                .catch(err => console.error('✗ Failed to terminate session:', err));
            
            console.log('SCORM API Finished');
            return 'true';
        },
        
        LMSGetValue: function(element) {
            if (!this._initialized) {
                this._errorCode = '301';
                return '';
            }
            
            if (this._finished) {
                this._errorCode = '101';
                return '';
            }
            
            console.log(`LMSGetValue called for: ${element}`);
            
            // In a real implementation, this would be synchronous from local cache
            // For now, we'll return empty and let the async call happen in background
            sendToBackend('GetValue', element, null)
                .then(data => {
                    console.log(`LMSGetValue(${element}):`, data.value);
                })
                .catch(err => console.error('LMSGetValue failed:', err));
            
            this._errorCode = '0';
            return ''; // SCORM requires synchronous return
        },
        
        LMSSetValue: function(element, value) {
            if (!this._initialized) {
                this._errorCode = '301';
                return 'false';
            }
            
            if (this._finished) {
                this._errorCode = '101';
                return 'false';
            }
            
            console.log(`LMSSetValue(${element}, ${value})`);
            
            sendToBackend('SetValue', element, value)
                .then(data => {
                    if (!data.success) {
                        console.error('✗ LMSSetValue failed on server');
                    } else {
                        console.log(`✓ LMSSetValue(${element}) saved`);
                    }
                })
                .catch(err => console.error('✗ LMSSetValue failed:', err));
            
            this._errorCode = '0';
            return 'true';
        },
        
        LMSCommit: function(parameter) {
            if (parameter !== '') {
                this._errorCode = '201';
                return 'false';
            }
            
            if (!this._initialized) {
                this._errorCode = '301';
                return 'false';
            }
            
            console.log('LMSCommit called');
            
            // Commit is implicit in our implementation since SetValue saves immediately
            this._errorCode = '0';
            return 'true';
        },
        
        LMSGetLastError: function() {
            return this._errorCode;
        },
        
        LMSGetErrorString: function(errorCode) {
            const errors = {
                '0': 'No error',
                '101': 'General exception',
                '201': 'Invalid argument error',
                '202': 'Element cannot have children',
                '203': 'Element not an array',
                '301': 'Not initialized',
                '401': 'Not implemented error',
                '402': 'Invalid set value',
                '403': 'Element is read only',
                '404': 'Element is write only',
                '405': 'Incorrect data type'
            };
            return errors[errorCode] || 'Unknown error';
        },
        
        LMSGetDiagnostic: function(errorCode) {
            return `Error ${errorCode}: ${this.LMSGetErrorString(errorCode)}`;
        }
    };
    
    // Also support SCORM 2004 API (basic compatibility)
    window.API_1484_11 = {
        Initialize: function(param) { return window.API.LMSInitialize(param); },
        Terminate: function(param) { return window.API.LMSFinish(param); },
        GetValue: function(element) { return window.API.LMSGetValue(element); },
        SetValue: function(element, value) { return window.API.LMSSetValue(element, value); },
        Commit: function(param) { return window.API.LMSCommit(param); },
        GetLastError: function() { return window.API.LMSGetLastError(); },
        GetErrorString: function(code) { return window.API.LMSGetErrorString(code); },
        GetDiagnostic: function(code) { return window.API.LMSGetDiagnostic(code); }
    };
    
    // Clean up on page unload
    window.addEventListener('beforeunload', () => {
        stopHeartbeat();
        if (window.API._initialized && !window.API._finished) {
            window.API.LMSFinish('');
        }
    });
    
    console.log('SCORM API Loaded (with auth & session tracking)', { 
        courseId, 
        userId, 
        sessionId,
        hasToken: !!getToken()
    });
})();