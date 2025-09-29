const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const unzipper = require('unzipper');
const xml2js = require('xml2js');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../../client')));
app.use('/courses', express.static(path.join(__dirname, '../uploads')));

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const uploadPath = path.join(__dirname, '../uploads');
        await fs.mkdir(uploadPath, { recursive: true });
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ 
    storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/zip' || file.originalname.endsWith('.zip')) {
            cb(null, true);
        } else {
            cb(new Error('Only ZIP files are allowed'));
        }
    }
});

// In-memory database for MVP (replace with real DB later)
const courses = new Map();
const progress = new Map();

// SCORM API endpoint
app.post('/api/scorm/:courseId/:learnerId', (req, res) => {
    const { courseId, learnerId } = req.params;
    const { action, element, value } = req.body;
    
    const progressKey = `${courseId}-${learnerId}`;
    
    if (!progress.has(progressKey)) {
        progress.set(progressKey, {
            'cmi.core.lesson_status': 'not attempted',
            'cmi.core.score.raw': '',
            'cmi.core.total_time': '0000:00:00',
            'cmi.core.session_time': '0000:00:00'
        });
    }
    
    const learnerData = progress.get(progressKey);
    
    switch(action) {
        case 'LMSInitialize':
            res.json({ result: 'true', error: '0' });
            break;
            
        case 'LMSFinish':
            res.json({ result: 'true', error: '0' });
            break;
            
        case 'LMSGetValue':
            const value = learnerData[element] || '';
            res.json({ result: value, error: '0' });
            break;
            
        case 'LMSSetValue':
            learnerData[element] = value;
            res.json({ result: 'true', error: '0' });
            break;
            
        case 'LMSCommit':
            progress.set(progressKey, learnerData);
            res.json({ result: 'true', error: '0' });
            break;
            
        default:
            res.json({ result: 'false', error: '201' });
    }
});

// Upload course endpoint
app.post('/api/courses/upload', upload.single('scormPackage'), async (req, res) => {
    try {
        const file = req.file;
        const courseId = Date.now().toString();
        const extractPath = path.join(__dirname, '../uploads', courseId);
        
        // Extract ZIP file
        await fs.mkdir(extractPath, { recursive: true });
        await fs.createReadStream(file.path)
            .pipe(unzipper.Extract({ path: extractPath }))
            .promise();
        
        // Parse manifest
        const manifestPath = path.join(extractPath, 'imsmanifest.xml');
        const manifestContent = await fs.readFile(manifestPath, 'utf8');
        const parser = new xml2js.Parser();
        const manifest = await parser.parseStringPromise(manifestContent);
        
        // Extract course info
        const organization = manifest.manifest.organizations[0].organization[0];
        const resource = manifest.manifest.resources[0].resource[0];
        
        const courseInfo = {
            id: courseId,
            title: organization.title?.[0] || 'Untitled Course',
            launchFile: resource.$.href,
            uploadedAt: new Date()
        };
        
        courses.set(courseId, courseInfo);
        
        // Clean up uploaded zip
        await fs.unlink(file.path);
        
        res.json({ success: true, course: courseInfo });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Failed to process SCORM package' });
    }
});

// Get all courses
app.get('/api/courses', (req, res) => {
    res.json(Array.from(courses.values()));
});

// Get course launch URL
app.get('/api/courses/:courseId/launch', (req, res) => {
    const course = courses.get(req.params.courseId);
    if (course) {
        const launchUrl = `/courses/${course.id}/${course.launchFile}`;
        res.json({ launchUrl });
    } else {
        res.status(404).json({ error: 'Course not found' });
    }
});

app.listen(PORT, () => {
    console.log(`SCORM Player running on port ${PORT}`);
});