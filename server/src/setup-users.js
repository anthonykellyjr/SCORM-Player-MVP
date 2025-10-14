const bcrypt = require('bcrypt');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

const BCRYPT_ROUNDS = 12;
const USERS_DB_PATH = path.join(__dirname, '../data/users.json');

async function setupUsers() {
    console.log('Creating user accounts...');
    
    const users = [
        {
            id: crypto.randomUUID(),
            email: 'anthony.d.kelly@gmail.com',
            password: await bcrypt.hash('Toyboat2', BCRYPT_ROUNDS),
            name: 'Anthony Kelly',
            role: 'admin',
            authProvider: 'local',
            createdAt: new Date().toISOString()
        },
        {
            id: crypto.randomUUID(),
            email: 'nathan@orthoskool.com',
            password: await bcrypt.hash('OrthoSkoolDev123', BCRYPT_ROUNDS),
            name: 'Nathan',
            role: 'admin',
            authProvider: 'local',
            createdAt: new Date().toISOString()
        },
        {
            id: crypto.randomUUID(),
            email: 'ryan@orthoskool.com',
            password: await bcrypt.hash('OrthoSkoolDev123', BCRYPT_ROUNDS),
            name: 'Ryan',
            role: 'admin',
            authProvider: 'local',
            createdAt: new Date().toISOString()
        },
        {
            id: crypto.randomUUID(),
            email: 'patient@example.com',
            password: await bcrypt.hash('TestPatient321', BCRYPT_ROUNDS),
            name: 'Test Patient',
            role: 'patient',
            authProvider: 'local',
            createdAt: new Date().toISOString()
        }
    ];
    
    await fs.mkdir(path.dirname(USERS_DB_PATH), { recursive: true });
    await fs.writeFile(USERS_DB_PATH, JSON.stringify(users, null, 2));
    
    console.log('Users created successfully!');
    console.log('\nCreated accounts:');
    users.forEach(user => {
        console.log(`${user.email} - Role: ${user.role}`);
    });
}

setupUsers().catch(console.error);