// SCORM API Implementation with Authentication & Session Management
(function() {
    'use strict';

    // Use current origin
    const API_URL = window.location.origin;
    console.log('SCORM API using:', API_URL);

    // Get URL parameters
    function getUrlParameter(name) {
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.get(name);
    }

    // Try to get token from multiple sources
    function getAuthToken() {
        // 1. Try parent window (if we're in an iframe)
        try {
            if (window.parent && window.parent !== window) {
                const parentToken = window.parent.localStorage.getItem('accessToken');
                if (parentToken) {
                    console.log('✓ Got token from parent window');
                    return parentToken;
                }
            }
        } catch (e) {
            console.log('Cannot access parent localStorage (cross-origin)');
        }

        // 2. Try current window localStorage
        const localToken = localStorage.getItem('accessToken');
        if (localToken) {
            console.log('✓ Got token from local storage');
            return localToken;
        }

        // 3. Try sessionStorage as fallback
        const sessionToken = sessionStorage.getItem('accessToken');
        if (sessionToken) {
            console.log('✓ Got token from session storage');
            return sessionToken;
        }

        console.warn('⚠ No auth token found in any location');
        return null;
    }

    const courseId = getUrlParameter('courseId');
    const userId = getUrlParameter('userId');
    const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    console.log('SCORM API Loaded (with auth & session tracking)', {
        courseId,
        userId,
        sessionId,
        hasToken: !!getAuthToken(),
        apiUrl: API_URL
    });

    // Session heartbeat to keep session alive
    let heartbeatInterval = null;
    
    function startHeartbeat() {
        console.log('Starting session heartbeat...');
        
        // Send heartbeat every 30 seconds
        heartbeatInterval = setInterval(async () => {
            await sendHeartbeat();
        }, 30000);
        
        // Send initial heartbeat
        sendHeartbeat();
    }

    async function sendHeartbeat() {
        const token = getAuthToken();
        if (!token) {
            console.log('No auth token available for heartbeat');
            return;
        }

        try {
            const response = await fetch(`${API_URL}/api/sessions/${sessionId}/heartbeat`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    courseId,
                    userId
                })
            });
            
            if (!response.ok) {
                console.error('Heartbeat failed:', response.status);
            }
        } catch (error) {
            console.error('Heartbeat failed:', error);
        }
    }

    function stopHeartbeat() {
        if (heartbeatInterval) {
            clearInterval(heartbeatInterval);
            heartbeatInterval = null;
            console.log('Session heartbeat stopped');
        }
    }

    // SCORM data store
    const scormData = {
        'cmi.core.student_id': userId || 'unknown',
        'cmi.core.student_name': 'Student',
        'cmi.core.lesson_location': '',
        'cmi.core.credit': 'credit',
        'cmi.core.lesson_status': 'not attempted',
        'cmi.core.entry': 'ab-initio',
        'cmi.core.score.raw': '',
        'cmi.core.score.max': '100',
        'cmi.core.score.min': '0',
        'cmi.core.total_time': '0000:00:00.00',
        'cmi.core.lesson_mode': 'normal',
        'cmi.core.exit': '',
        'cmi.core.session_time': '0000:00:00.00',
        'cmi.suspend_data': '',
        'cmi.launch_data': '',
        'cmi.comments': '',
        'cmi.comments_from_lms': ''
    };

    // Helper function to send data to backend
    async function sendToBackend(endpoint, data) {
        const token = getAuthToken();
        if (!token) {
            console.error('No auth token available');
            throw new Error('No authentication');
        }

        try {
            const response = await fetch(`${API_URL}${endpoint}`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    courseId,
                    userId,
                    ...data
                })
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`HTTP ${response.status}: ${errorText}`);
            }

            return await response.json();
        } catch (error) {
            console.error('Backend request failed:', error);
            throw error;
        }
    }

    // SCORM API 1.2 Implementation
    window.API = {
        _initialized: false,
        _finished: false,
        _lastError: '0',
        courseId: courseId,
        userId: userId,
        sessionId: sessionId,

        LMSInitialize: function(param) {
            console.log('LMSInitialize called', {
                alreadyInitialized: this._initialized,
                finished: this._finished,
                hasToken: !!getAuthToken()
            });
            
            if (this._initialized) {
                console.warn('Already initialized, returning false');
                this._lastError = '101'; // Already initialized
                return 'false';
            }

            if (!getAuthToken()) {
                console.error('❌ No auth token - cannot initialize');
                this._lastError = '101';
                return 'false';
            }

            this._initialized = true;
            this._finished = false;
            this._lastError = '0';
            
            // Start session heartbeat
            startHeartbeat();

            // Initialize session on backend
            sendToBackend('/api/scorm/initialize', {
                sessionId: sessionId
            }).then(() => {
                console.log('✅ SCORM session initialized on backend');
            }).catch(error => {
                console.error('❌ Failed to initialize session on backend:', error);
                // Don't fail the initialization - the content can still work locally
            });

            console.log('✅ LMSInitialize returning true');
            return 'true';
        },

        LMSFinish: function(param) {
            console.log('LMSFinish called');
            
            if (!this._initialized) {
                this._lastError = '301'; // Not initialized
                return 'false';
            }

            if (this._finished) {
                this._lastError = '101'; // Already finished
                return 'false';
            }

            this._finished = true;
            
            // Stop heartbeat
            stopHeartbeat();

            // Commit final data
            this.LMSCommit('');

            // Terminate session on backend
            sendToBackend('/api/scorm/terminate', {
                sessionId: sessionId
            }).then(() => {
                console.log('✅ SCORM session terminated');
            }).catch(error => {
                console.error('❌ Failed to terminate session:', error);
            });

            return 'true';
        },

        LMSGetValue: function(element) {
            console.log('LMSGetValue called for:', element);
            
            if (!this._initialized || this._finished) {
                this._lastError = '301';
                return '';
            }

            // Fetch from backend (async - don't wait for it)
            sendToBackend('/api/scorm/getValue', {
                element: element
            }).then(response => {
                if (response.value !== undefined) {
                    scormData[element] = response.value;
                }
            }).catch(error => {
                console.error('LMSGetValue backend failed:', error);
            });

            const value = scormData[element] !== undefined ? scormData[element] : '';
            this._lastError = '0';
            return value;
        },

        LMSSetValue: function(element, value) {
            console.log(`LMSSetValue(${element}, ${value})`);
            
            if (!this._initialized || this._finished) {
                this._lastError = '301';
                return 'false';
            }

            if (scormData.hasOwnProperty(element)) {
                scormData[element] = value;
                this._lastError = '0';
                
                // Send to backend (async - don't wait for it)
                sendToBackend('/api/scorm/setValue', {
                    element: element,
                    value: value
                }).catch(error => {
                    console.error('LMSSetValue backend failed:', error);
                });
                
                return 'true';
            }

            this._lastError = '401'; // Not implemented element
            return 'false';
        },

        LMSCommit: function(param) {
            console.log('LMSCommit called');
            
            if (!this._initialized || this._finished) {
                this._lastError = '301';
                return 'false';
            }

            this._lastError = '0';
            return 'true';
        },

        LMSGetLastError: function() {
            return this._lastError;
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

    // Cleanup on page unload
    window.addEventListener('beforeunload', function() {
        if (window.API && window.API._initialized && !window.API._finished) {
            window.API.LMSFinish('');
        }
    });

    console.log('✅ SCORM API 1.2 ready');
})();