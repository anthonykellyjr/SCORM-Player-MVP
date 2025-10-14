/**
 * app.js - SCORM Player Server with OAuth Authentication
 * Enhanced security implementation for OrthoSkool LMS
 */

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const fsPromises = require('fs').promises;
const unzipper = require('unzipper');
const xml2js = require('xml2js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config({ path: '../../.env' });

// ===== CONFIGURATION =====
const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Security Configuration
const JWT_SECRET = process.env.JWT_SECRET || (NODE_ENV === 'development' ? crypto.randomBytes(64).toString('hex') : null);
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || (NODE_ENV === 'development' ? crypto.randomBytes(64).toString('hex') : null);
const SESSION_SECRET = process.env.SESSION_SECRET || (NODE_ENV === 'development' ? crypto.randomBytes(32).toString('hex') : null);
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 12;

// Validate required environment variables in production
if (NODE_ENV === 'production') {
    const requiredEnvVars = ['JWT_SECRET', 'JWT_REFRESH_SECRET', 'SESSION_SECRET'];
    const missing = requiredEnvVars.filter(varName => !process.env[varName]);
    
    if (missing.length > 0) {
        console.error('❌ Missing required environment variables:', missing.join(', '));
        process.exit(1);
    }
}

// Development warnings
if (NODE_ENV === 'development' && !process.env.JWT_SECRET) {
    console.warn('⚠️  Development mode: Using auto-generated secrets (will change on restart)');
}

// OAuth Configuration
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const MICROSOFT_CLIENT_ID = process.env.MICROSOFT_CLIENT_ID;
const MICROSOFT_CLIENT_SECRET = process.env.MICROSOFT_CLIENT_SECRET;
const OAUTH_CALLBACK_BASE = process.env.OAUTH_CALLBACK_BASE || `http://localhost:${PORT}`;
const ALLOWED_ADMIN_DOMAINS = (process.env.ALLOWED_ADMIN_DOMAINS || 'orthoskool.com').split(',');

// Database paths
const COURSES_DB_PATH = path.join(__dirname, '../data/courses.json');
const USERS_DB_PATH = path.join(__dirname, '../data/users.json');
const REFRESH_TOKENS_PATH = path.join(__dirname, '../data/refresh_tokens.json');

// ===== SECURITY MIDDLEWARE =====

// Helmet for security headers - CSP for SCORM and Google Analytics
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://www.googletagmanager.com"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:", "blob:", "https://www.google-analytics.com"],
            mediaSrc: ["'self'", "data:", "blob:"],
            connectSrc: ["'self'", "https://metrics.articulate.com", "https://www.google-analytics.com", "https://analytics.google.com"],
            fontSrc: ["'self'", "data:"],
            objectSrc: ["'none'"],
            frameSrc: ["'self'"],
        },
    },
}));

// Rate limiting configurations
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 login attempts per window
    message: 'Too many login attempts. Please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
    trustProxy: true
});

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    trustProxy: true
});

// Apply rate limiting
app.use('/api/auth/login', loginLimiter);
app.use('/api/auth/oauth', loginLimiter);
app.use('/api', generalLimiter);

// Session configuration
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: NODE_ENV === 'production', // HTTPS only in production
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'strict'
    }
}));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// CORS configuration
app.use(cors({
    origin: function(origin, callback) {
        const allowedOrigins = [
            'http://localhost:3000',
            'http://localhost:3001', // Dev frontend
            'https://dev.orthoskool.com',
            'https://orthoskool.com'
        ];
        
        // Allow requests with no origin (mobile apps, postman, etc) in development
        if (!origin && NODE_ENV === 'development') return callback(null, true);
        
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

// Body parser middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Static files - UPDATED paths
app.use(express.static(path.join(__dirname, '../../client')));
app.use('/courses', express.static(path.join(__dirname, '../uploads')));

// ===== IN-MEMORY DATABASES =====
const courses = new Map();
const progress = new Map();
const users = new Map();
const refreshTokens = new Map();
const activeSessions = new Map();
const failedLoginAttempts = new Map(); // Track failed login attempts

// ===== OAUTH STRATEGIES =====

// Google OAuth Strategy
if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: `${OAUTH_CALLBACK_BASE}/auth/google/callback`,
        scope: ['profile', 'email']
    },
    async function(accessToken, refreshToken, profile, done) {
        try {
            const email = profile.emails[0].value;
            const domain = email.split('@')[1];
            
            // Check if email domain is allowed for admin access
            const isAdminDomain = ALLOWED_ADMIN_DOMAINS.includes(domain);
            
            // Find or create user
            let user = Array.from(users.values()).find(u => u.email === email);
            
            if (!user) {
                // Create new user
                user = {
                    id: crypto.randomUUID(),
                    email: email,
                    name: profile.displayName,
                    role: isAdminDomain ? 'admin' : 'student',
                    authProvider: 'google',
                    googleId: profile.id,
                    createdAt: new Date().toISOString(),
                    lastLogin: new Date().toISOString()
                };
                
                users.set(user.id, user);
                await saveUsersToDisk();
                
                console.log(`✅ New user created via Google OAuth: ${user.email} (${user.role})`);
            } else {
                // Update last login
                user.lastLogin = new Date().toISOString();
                await saveUsersToDisk();
            }
            
            return done(null, user);
        } catch (error) {
            console.error('Google OAuth error:', error);
            return done(error, null);
        }
    }));
    
    console.log('✅ Google OAuth configured');
} else {
    console.warn('⚠️  Google OAuth not configured (missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET)');
}

// Microsoft OAuth Strategy (optional)
const MicrosoftStrategy = require('passport-microsoft').Strategy;

if (MICROSOFT_CLIENT_ID && MICROSOFT_CLIENT_SECRET) {
    passport.use(new MicrosoftStrategy({
        clientID: MICROSOFT_CLIENT_ID,
        clientSecret: MICROSOFT_CLIENT_SECRET,
        callbackURL: `${OAUTH_CALLBACK_BASE}/auth/microsoft/callback`,
        scope: ['user.read']
    },
    async function(accessToken, refreshToken, profile, done) {
        try {
            const email = profile.emails[0].value;
            const domain = email.split('@')[1];
            
            const isAdminDomain = ALLOWED_ADMIN_DOMAINS.includes(domain);
            
            let user = Array.from(users.values()).find(u => u.email === email);
            
            if (!user) {
                user = {
                    id: crypto.randomUUID(),
                    email: email,
                    name: profile.displayName,
                    role: isAdminDomain ? 'admin' : 'student',
                    authProvider: 'microsoft',
                    microsoftId: profile.id,
                    createdAt: new Date().toISOString(),
                    lastLogin: new Date().toISOString()
                };
                
                users.set(user.id, user);
                await saveUsersToDisk();
                
                console.log(`✅ New user created via Microsoft OAuth: ${user.email} (${user.role})`);
            } else {
                user.lastLogin = new Date().toISOString();
                await saveUsersToDisk();
            }
            
            return done(null, user);
        } catch (error) {
            console.error('Microsoft OAuth error:', error);
            return done(error, null);
        }
    }));
    
    console.log('✅ Microsoft OAuth configured');
} else {
    console.warn('⚠️  Microsoft OAuth not configured (optional)');
}

// Passport serialization
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    const user = users.get(id);
    done(null, user);
});

// ===== JWT UTILITIES =====

function generateTokens(user) {
    const accessToken = jwt.sign(
        {
            id: user.id,
            email: user.email,
            role: user.role,
            name: user.name
        },
        JWT_SECRET,
        { expiresIn: '15m' } // Short-lived access token
    );
    
    const refreshToken = jwt.sign(
        {
            id: user.id,
            tokenId: crypto.randomUUID() // Unique ID for this refresh token
        },
        JWT_REFRESH_SECRET,
        { expiresIn: '7d' }
    );
    
    // Store refresh token
    refreshTokens.set(refreshToken, {
        userId: user.id,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
    });
    
    return { accessToken, refreshToken };
}

// ===== AUTH MIDDLEWARE =====

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
            }
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}

function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
}

// ===== USER DATABASE FUNCTIONS =====

async function loadUsersFromDisk() {
    try {
        await fsPromises.mkdir(path.dirname(USERS_DB_PATH), { recursive: true });
        const data = await fsPromises.readFile(USERS_DB_PATH, 'utf8');
        const usersArray = JSON.parse(data);
        
        // Migrate old users if needed
        for (const user of usersArray) {
            // Add missing fields for existing users
            if (!user.authProvider) {
                user.authProvider = 'local';
            }
            if (!user.createdAt) {
                user.createdAt = new Date().toISOString();
            }
            users.set(user.id, user);
        }
        
        console.log(`Loaded ${users.size} users from disk`);
    } catch (error) {
        console.log('No existing users database found, creating default admin...');
        await createDefaultAdmin();
    }
}

async function saveUsersToDisk() {
    try {
        await fsPromises.mkdir(path.dirname(USERS_DB_PATH), { recursive: true });
        const usersArray = Array.from(users.values());
        await fsPromises.writeFile(USERS_DB_PATH, JSON.stringify(usersArray, null, 2));
    } catch (error) {
        console.error('Failed to save users:', error);
    }
}

async function createDefaultAdmin() {
    // Only create ONE default admin for initial setup
    const defaultAdmin = {
        id: crypto.randomUUID(),
        email: 'admin@orthoskool.com',
        password: await bcrypt.hash('ChangeThisPassword123!', BCRYPT_ROUNDS),
        name: 'Default Admin',
        role: 'admin',
        authProvider: 'local',
        createdAt: new Date().toISOString(),
        mustChangePassword: true // Flag to force password change on first login
    };
    
    users.set(defaultAdmin.id, defaultAdmin);
    await saveUsersToDisk();
    
    console.log('⚠️  Default admin created. Email: admin@orthoskool.com');
    console.log('⚠️  IMPORTANT: Change the default password immediately!');
}

// ===== COURSE DATABASE FUNCTIONS =====

async function loadCoursesFromDisk() {
    try {
        await fsPromises.mkdir(path.dirname(COURSES_DB_PATH), { recursive: true });
        const data = await fsPromises.readFile(COURSES_DB_PATH, 'utf8');
        const coursesArray = JSON.parse(data);
        coursesArray.forEach(course => courses.set(course.id, course));
        console.log(`Loaded ${courses.size} courses from disk`);
    } catch (error) {
        console.log('No existing courses database found');
    }
}

async function saveCoursesToDisk() {
    try {
        await fsPromises.mkdir(path.dirname(COURSES_DB_PATH), { recursive: true });
        const coursesArray = Array.from(courses.values());
        await fsPromises.writeFile(COURSES_DB_PATH, JSON.stringify(coursesArray, null, 2));
    } catch (error) {
        console.error('Failed to save courses:', error);
    }
}

// ===== INITIALIZE SERVER =====

async function initializeServer() {
    await loadUsersFromDisk();
    await loadCoursesFromDisk();
    
    app.listen(PORT, () => {
        console.log(`\n🚀 OrthoSkool LMS Server`);
        console.log(`📍 Port: ${PORT}`);
        console.log(`🔒 Environment: ${NODE_ENV}`);
        console.log(`🔐 OAuth Providers: ${[
            GOOGLE_CLIENT_ID && 'Google',
            MICROSOFT_CLIENT_ID && 'Microsoft'
        ].filter(Boolean).join(', ') || 'None configured'}`);
        console.log(`\n===== Active Users =====`);
        
        users.forEach(user => {
            const icon = user.role === 'admin' ? '👑' : '👤';
            const auth = user.authProvider || 'local';
            console.log(`${icon} ${user.name} (${user.email}) - ${user.role} [${auth}]`);
        });
        
        console.log('========================\n');
    });
}

// Initialize server
initializeServer();

// ===== AUTH ROUTES =====

// OAuth Routes - Google
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login?error=oauth_failed' }),
    async (req, res) => {
        // Generate JWT tokens for the authenticated user
        const { accessToken, refreshToken } = generateTokens(req.user);
        
        // In production, you'd want to pass these tokens securely to the frontend
        // For now, we'll redirect with tokens in URL (not ideal for production)
        res.redirect(`/dashboard?token=${accessToken}&refresh=${refreshToken}`);
    }
);

// OAuth Routes - Microsoft
app.get('/auth/microsoft',
    passport.authenticate('microsoft')
);

app.get('/auth/microsoft/callback',
    passport.authenticate('microsoft', { failureRedirect: '/login?error=oauth_failed' }),
    async (req, res) => {
        const { accessToken, refreshToken } = generateTokens(req.user);
        res.redirect(`/dashboard?token=${accessToken}&refresh=${refreshToken}`);
    }
);

// Traditional login (with enhanced security)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }
        
        // Check for too many failed attempts
        const attemptsKey = `${email}_${req.ip}`;
        const attempts = failedLoginAttempts.get(attemptsKey) || { count: 0, lastAttempt: Date.now() };
        
        // Reset attempts if last attempt was more than 15 minutes ago
        if (Date.now() - attempts.lastAttempt > 15 * 60 * 1000) {
            attempts.count = 0;
        }
        
        if (attempts.count >= 5) {
            return res.status(429).json({ 
                error: 'Account locked due to too many failed attempts. Please try again later.' 
            });
        }
        
        // Find user by email
        const user = Array.from(users.values()).find(u => u.email === email && u.authProvider === 'local');
        
        if (!user) {
            attempts.count++;
            attempts.lastAttempt = Date.now();
            failedLoginAttempts.set(attemptsKey, attempts);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            attempts.count++;
            attempts.lastAttempt = Date.now();
            failedLoginAttempts.set(attemptsKey, attempts);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Clear failed attempts on successful login
        failedLoginAttempts.delete(attemptsKey);
        
        // Update last login
        user.lastLogin = new Date().toISOString();
        await saveUsersToDisk();
        
        // Generate tokens
        const { accessToken, refreshToken } = generateTokens(user);
        
        res.json({
            accessToken,
            refreshToken,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
                mustChangePassword: user.mustChangePassword
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Refresh token endpoint
app.post('/api/auth/refresh', async (req, res) => {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
        return res.status(401).json({ error: 'Refresh token required' });
    }
    
    // Check if refresh token exists and is valid
    const tokenData = refreshTokens.get(refreshToken);
    if (!tokenData) {
        return res.status(403).json({ error: 'Invalid refresh token' });
    }
    
    // Check if token is expired
    if (new Date(tokenData.expiresAt) < new Date()) {
        refreshTokens.delete(refreshToken);
        return res.status(403).json({ error: 'Refresh token expired' });
    }
    
    try {
        // Verify the refresh token
        const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
        const user = users.get(decoded.id);
        
        if (!user) {
            return res.status(403).json({ error: 'User not found' });
        }
        
        // Generate new tokens
        const tokens = generateTokens(user);
        
        // Delete old refresh token
        refreshTokens.delete(refreshToken);
        
        res.json(tokens);
    } catch (error) {
        console.error('Token refresh error:', error);
        res.status(403).json({ error: 'Invalid refresh token' });
    }
});

// Logout endpoint
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
    const { refreshToken } = req.body;
    
    // Remove refresh token if provided
    if (refreshToken) {
        refreshTokens.delete(refreshToken);
    }
    
    res.json({ success: true, message: 'Logged out successfully' });
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
    const user = users.get(req.user.id);
    if (user) {
        res.json({
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
            authProvider: user.authProvider
        });
    } else {
        res.status(404).json({ error: 'User not found' });
    }
});

// Change password endpoint (for local auth users)
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const user = users.get(req.user.id);
        
        if (!user || user.authProvider !== 'local') {
            return res.status(400).json({ error: 'Password change not available for OAuth users' });
        }
        
        // Validate current password
        const validPassword = await bcrypt.compare(currentPassword, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }
        
        // Validate new password strength
        if (!isStrongPassword(newPassword)) {
            return res.status(400).json({ 
                error: 'Password must be at least 8 characters with uppercase, lowercase, number, and special character' 
            });
        }
        
        // Hash and save new password
        user.password = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
        user.mustChangePassword = false;
        user.passwordChangedAt = new Date().toISOString();
        
        await saveUsersToDisk();
        
        res.json({ success: true, message: 'Password changed successfully' });
    } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// Password strength validator
function isStrongPassword(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    return password.length >= minLength && 
           hasUpperCase && 
           hasLowerCase && 
           hasNumbers && 
           hasSpecialChar;
}

// ===== MULTER CONFIGURATION =====

const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const uploadPath = path.join(__dirname, '../uploads');
        await fsPromises.mkdir(uploadPath, { recursive: true });
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({
    storage,
    limits: {
        fileSize: 500 * 1024 * 1024 // 500MB limit
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/zip' || file.originalname.endsWith('.zip')) {
            cb(null, true);
        } else {
            cb(new Error('Only ZIP files are allowed'));
        }
    }
});

// ===== COURSE ROUTES (Protected) =====

app.get('/api/courses', authenticateToken, (req, res) => {
    res.json(Array.from(courses.values()));
});

app.get('/api/courses/:courseId/launch', authenticateToken, (req, res) => {
    const course = courses.get(req.params.courseId);
    if (course) {
        const launchUrl = `/courses/${course.id}/${course.launchFile}`;
        res.json({ launchUrl });
    } else {
        res.status(404).json({ error: 'Course not found' });
    }
});

app.post('/api/courses/upload', authenticateToken, requireAdmin, upload.single('scormPackage'), async (req, res) => {
    console.log('Upload started:', req.file?.filename);
    
    try {
        const file = req.file;
        if (!file) {
            throw new Error('No file uploaded');
        }
        
        const courseId = Date.now().toString();
        const extractPath = path.join(__dirname, '../uploads', courseId);
        
        console.log('Creating directory:', extractPath);
        await fsPromises.mkdir(extractPath, { recursive: true });
        
        console.log('Starting extraction...');
        await fs.createReadStream(file.path)
            .pipe(unzipper.Extract({ path: extractPath }))
            .promise();
        
        console.log('Extraction complete, looking for manifest...');
        const manifestPath = path.join(extractPath, 'imsmanifest.xml');
        
        const manifestContent = await fsPromises.readFile(manifestPath, 'utf8');
        const parser = new xml2js.Parser();
        const manifest = await parser.parseStringPromise(manifestContent);
        
        console.log('Manifest parsed successfully');
        
        const organization = manifest.manifest.organizations[0].organization[0];
        const resource = manifest.manifest.resources[0].resource[0];
        
        const courseInfo = {
            id: courseId,
            title: organization.title?.[0] || 'Untitled Course',
            launchFile: resource.$.href,
            uploadedAt: new Date().toISOString(),
            uploadedBy: req.user.email
        };
        
        courses.set(courseId, courseInfo);
        await saveCoursesToDisk();
        
        await fsPromises.unlink(file.path);
        
        console.log('Course uploaded successfully:', courseInfo);
        res.json({ success: true, course: courseInfo });
    } catch (error) {
        console.error('Upload error details:', error);
        res.status(500).json({ error: 'Failed to process SCORM package: ' + error.message });
    }
});

app.delete('/api/courses/:courseId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const courseId = req.params.courseId;
        
        if (courses.has(courseId)) {
            courses.delete(courseId);
            await saveCoursesToDisk();
            
            const coursePath = path.join(__dirname, '../uploads', courseId);
            await fsPromises.rm(coursePath, { recursive: true, force: true });
            
            res.json({ success: true });
        } else {
            res.status(404).json({ error: 'Course not found' });
        }
    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({ error: 'Failed to delete course' });
    }
});

// ===== SCORM API ROUTES - COMPLETELY REWRITTEN =====

// Initialize SCORM session
app.post('/api/scorm/initialize', authenticateToken, (req, res) => {
    const { courseId, userId, sessionId } = req.body;
    
    console.log('SCORM Initialize called:', { courseId, userId, sessionId });
    
    if (!courseId || !userId) {
        return res.status(400).json({ error: 'Missing required fields: courseId, userId' });
    }
    
    if (req.user.id !== userId && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const progressKey = `${userId}-${courseId}`;
    
    if (!progress.has(progressKey)) {
        const course = courses.get(courseId);
        progress.set(progressKey, {
            userId,
            courseId,
            courseName: course?.title || 'Unknown Course',
            scormData: {},
            lessonStatus: 'not attempted',
            score: null,
            sessionTime: '00:00:00',
            suspendData: '',
            location: '',
            lastAccessed: new Date().toISOString(),
            attempts: 1,
            firstAttempt: new Date().toISOString()
        });
    }
    
    if (sessionId) {
        activeSessions.set(sessionId, {
            courseId,
            userId,
            startTime: Date.now(),
            lastActivity: Date.now()
        });
    }
    
    console.log('✅ SCORM session initialized');
    res.json({ success: true });
});

// Get SCORM value
app.post('/api/scorm/getValue', authenticateToken, (req, res) => {
    const { courseId, userId, element } = req.body;
    
    console.log('SCORM GetValue called:', { courseId, userId, element });
    
    if (!courseId || !userId || !element) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    
    if (req.user.id !== userId && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const progressKey = `${userId}-${courseId}`;
    const userProgress = progress.get(progressKey);
    
    if (!userProgress) {
        console.log('No progress found, returning empty value');
        return res.json({ success: true, value: '' });
    }
    
    const value = userProgress.scormData[element] || '';
    console.log(`✅ Returning value for ${element}:`, value);
    res.json({ success: true, value });
});

// Set SCORM value
app.post('/api/scorm/setValue', authenticateToken, (req, res) => {
    const { courseId, userId, element, value } = req.body;
    
    console.log('SCORM SetValue called:', { courseId, userId, element, value });
    
    if (!courseId || !userId || !element) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    
    if (req.user.id !== userId && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const progressKey = `${userId}-${courseId}`;
    const userProgress = progress.get(progressKey);
    
    if (!userProgress) {
        return res.status(404).json({ error: 'Progress not found - call initialize first' });
    }
    
    userProgress.scormData[element] = value;
    userProgress.lastAccessed = new Date().toISOString();
    
    // Update specific fields
    switch (element) {
        case 'cmi.core.lesson_status':
            userProgress.lessonStatus = value;
            console.log(`Updated lesson status to: ${value}`);
            break;
        case 'cmi.core.score.raw':
            userProgress.score = parseInt(value) || 0;
            console.log(`Updated score to: ${userProgress.score}`);
            break;
        case 'cmi.core.session_time':
            userProgress.sessionTime = value;
            break;
        case 'cmi.suspend_data':
            userProgress.suspendData = value;
            break;
        case 'cmi.core.lesson_location':
            userProgress.location = value;
            break;
    }
    
    console.log('✅ Value set successfully');
    res.json({ success: true });
});

// Terminate SCORM session
app.post('/api/scorm/terminate', authenticateToken, (req, res) => {
    const { sessionId, courseId, userId } = req.body;
    
    console.log('SCORM Terminate called:', { sessionId, courseId, userId });
    
    if (sessionId) {
        activeSessions.delete(sessionId);
        console.log('✅ Session terminated');
    }
    
    res.json({ success: true });
});

// Session heartbeat - FIXED ROUTE
app.post('/api/sessions/:sessionId/heartbeat', authenticateToken, (req, res) => {
    const { sessionId } = req.params;
    const { courseId, userId } = req.body;
    
    console.log('Heartbeat received:', { sessionId, courseId, userId });
    
    if (!courseId || !userId) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    
    if (req.user.id !== userId && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const now = Date.now();
    
    if (activeSessions.has(sessionId)) {
        const session = activeSessions.get(sessionId);
        session.lastActivity = now;
    } else {
        activeSessions.set(sessionId, {
            courseId,
            userId,
            startTime: now,
            lastActivity: now
        });
    }
    
    // Cleanup old sessions
    const fiveMinutesAgo = now - (5 * 60 * 1000);
    for (const [id, session] of activeSessions.entries()) {
        if (session.lastActivity < fiveMinutesAgo) {
            activeSessions.delete(id);
        }
    }
    
    console.log(`✅ Heartbeat updated. Active sessions: ${activeSessions.size}`);
    
    res.json({
        success: true,
        activeSessions: activeSessions.size
    });
});

// ===== PROGRESS & STATS ROUTES =====

app.get('/api/progress', authenticateToken, (req, res) => {
    const { userId, courseId } = req.query;
    
    let progressArray = Array.from(progress.values());
    
    if (req.user.role !== 'admin') {
        progressArray = progressArray.filter(p => p.userId === req.user.id);
    } else {
        if (userId && userId !== 'all') {
            progressArray = progressArray.filter(p => p.userId === userId);
        }
        
        if (courseId && courseId !== 'all') {
            progressArray = progressArray.filter(p => p.courseId === courseId);
        }
    }
    
    progressArray = progressArray.map(p => {
        let progressPercent = 0;
        
        if (p.lessonStatus === 'completed' || p.lessonStatus === 'passed') {
            progressPercent = 100;
        } else if (p.lessonStatus === 'incomplete') {
            progressPercent = 50;
        } else if (p.lessonStatus === 'failed') {
            progressPercent = 100;
        } else if (p.location && p.location !== '') {
            progressPercent = 25;
        }
        
        return {
            ...p,
            progressPercent,
            displayStatus: p.lessonStatus || 'not attempted'
        };
    });
    
    res.json(progressArray);
});

app.get('/api/stats/summary', authenticateToken, (req, res) => {
    const totalCourses = courses.size;
    const totalUsers = new Set(Array.from(progress.values()).map(p => p.userId)).size;
    const totalSessions = progress.size;
    const activeSessionsCount = activeSessions.size;
    
    const completed = Array.from(progress.values()).filter(
        p => p.lessonStatus === 'completed' || p.lessonStatus === 'passed'
    ).length;
    
    const completionRate = totalSessions > 0
        ? Math.round((completed / totalSessions) * 100)
        : 0;
    
    const scoresArray = Array.from(progress.values())
        .filter(p => p.score !== null && p.score !== undefined)
        .map(p => p.score);
    
    const averageScore = scoresArray.length > 0
        ? Math.round(scoresArray.reduce((a, b) => a + b, 0) / scoresArray.length)
        : 0;
    
    res.json({
        totalCourses,
        totalUsers,
        totalSessions,
        activeSessions: activeSessionsCount,
        completionRate,
        averageScore,
        completed,
        inProgress: totalSessions - completed
    });
});

// ===== ADMIN ROUTES =====

app.get('/api/admin/activity', authenticateToken, requireAdmin, (req, res) => {
    try {
        const activities = [];
        
        for (const [key, data] of progress.entries()) {
            const [userId, courseId] = key.split('-');
            
            const course = courses.get(courseId);
            const user = users.get(userId);
            
            activities.push({
                userId,
                userName: user ? user.name : 'Unknown User',
                userEmail: user ? user.email : 'Unknown',
                courseId,
                courseTitle: course ? course.title : 'Unknown Course',
                status: data.lessonStatus || 'not-attempted',
                score: data.score || null,
                timeSpent: data.sessionTime || null,
                lastAccessed: data.lastAccessed || new Date().toISOString()
            });
        }
        
        res.json(activities);
    } catch (error) {
        console.error('Error fetching activity:', error);
        res.status(500).json({ error: 'Failed to fetch activity data' });
    }
});

app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
    const userList = Array.from(users.values()).map(user => ({
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        authProvider: user.authProvider,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
    }));
    res.json(userList);
});

// Get course-specific statistics
app.get('/api/stats/courses', authenticateToken, (req, res) => {
    const courseStats = [];
    
    courses.forEach(course => {
        const courseProgress = Array.from(progress.values())
            .filter(p => p.courseId === course.id);
        
        const completed = courseProgress.filter(
            p => p.lessonStatus === 'completed' || p.lessonStatus === 'passed'
        ).length;
        
        const scores = courseProgress
            .filter(p => p.score !== null && p.score !== undefined)
            .map(p => p.score);
        
        const avgScore = scores.length > 0
            ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length)
            : 0;
        
        courseStats.push({
            courseId: course.id,
            courseName: course.title,
            totalEnrollments: courseProgress.length,
            completed,
            completionRate: courseProgress.length > 0 
                ? Math.round((completed / courseProgress.length) * 100)
                : 0,
            averageScore: avgScore
        });
    });
    
    res.json(courseStats);
});

// Get active sessions details
app.get('/api/sessions/active', authenticateToken, (req, res) => {
    const now = Date.now();
    const activeSessionsList = Array.from(activeSessions.entries()).map(([sessionId, session]) => {
        const durationMs = now - session.startTime;
        const durationMin = Math.floor(durationMs / 60000);
        
        const course = courses.get(session.courseId);
        
        return {
            sessionId,
            userId: session.userId,
            courseId: session.courseId,
            courseName: course?.title || 'Unknown',
            startTime: new Date(session.startTime).toISOString(),
            duration: `${durationMin} min`,
            lastActivity: new Date(session.lastActivity).toISOString()
        };
    });
    
    res.json(activeSessionsList);
});

module.exports = app;