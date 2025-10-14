const fs = require('fs').promises;
const path = require('path');
const xml2js = require('xml2js');

async function reload() {
    const uploadsDir = path.join(__dirname, 'uploads');
    const folders = await fs.readdir(uploadsDir);
    const courses = [];
    
    for (const folder of folders) {
        try {
            const manifestPath = path.join(uploadsDir, folder, 'imsmanifest.xml');
            const manifestContent = await fs.readFile(manifestPath, 'utf8');
            const parser = new xml2js.Parser();
            const manifest = await parser.parseStringPromise(manifestContent);
            
            const organization = manifest.manifest.organizations[0].organization[0];
            const resource = manifest.manifest.resources[0].resource[0];
            
            courses.push({
                id: folder,
                title: organization.title?.[0] || 'Untitled Course',
                launchFile: resource.$.href,
                uploadedAt: new Date()
            });
        } catch (e) {
            console.log(`Skipping ${folder}:`, e.message);
        }
    }
    
    await fs.writeFile('courses.json', JSON.stringify(courses, null, 2));
    console.log(`Created courses.json with ${courses.length} courses`);
}

reload();