// Admin Dashboard JavaScript
let allProgressData = [];
let currentUser = null;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', async () => {
    if (!requireAuth('admin')) return;
    
    currentUser = JSON.parse(localStorage.getItem('user'));
    document.getElementById('user-name').textContent = currentUser.name;
    
    await refreshData();
    setInterval(refreshData, 30000); // Auto-refresh every 30 seconds
    // Add event listeners
    document.getElementById('refreshBtn').addEventListener('click', refreshData);
    document.getElementById('logoutBtn').addEventListener('click', logout);
    document.getElementById('userFilter').addEventListener('change', filterData);
    document.getElementById('courseFilter').addEventListener('change', filterData);
});

async function refreshData() {
    console.log('Refreshing dashboard data...');
    await Promise.all([
        loadSummaryStats(),
        loadActiveSessions(),
        loadProgressData(),
        loadCourseStats()
    ]);
}

async function loadSummaryStats() {
    try {
        const stats = await apiRequest('/api/stats/summary');
        document.getElementById('totalCourses').textContent = stats.totalCourses || 0;
        document.getElementById('totalUsers').textContent = stats.totalUsers || 0;
        document.getElementById('activeSessions').textContent = stats.activeSessions || 0;
        document.getElementById('completionRate').textContent = `${stats.completionRate || 0}%`;
        document.getElementById('averageScore').textContent = `${stats.averageScore || 0}%`;
    } catch (error) {
        console.error('Failed to load summary stats:', error);
    }
}

async function loadActiveSessions() {
    try {
        const sessions = await apiRequest('/api/sessions/active');
        const users = await apiRequest('/api/admin/users');
        const userMap = {};
        users.forEach(u => userMap[u.id] = u);

        const tbody = document.getElementById('activeSessionsBody');
        
        if (sessions.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No active sessions</td></tr>';
            return;
        }

        tbody.innerHTML = sessions.map(session => {
            const user = userMap[session.userId];
            const userName = user ? user.name : `User ${session.userId}`;
            
            return `
                <tr>
                    <td><strong>${userName}</strong></td>
                    <td>${session.courseName}</td>
                    <td>${formatTime(session.startTime)}</td>
                    <td><span class="badge badge-active">${session.duration}</span></td>
                    <td>${formatTime(session.lastActivity)}</td>
                </tr>
            `;
        }).join('');
    } catch (error) {
        console.error('Failed to load active sessions:', error);
    }
}

async function loadProgressData() {
    try {
        allProgressData = await apiRequest('/api/progress');
        populateFilters();
        displayProgressData(allProgressData);
    } catch (error) {
        console.error('Failed to load progress data:', error);
    }
}

async function loadCourseStats() {
    try {
        const courseStats = await apiRequest('/api/stats/courses');
        const tbody = document.getElementById('courseStatsBody');
        
        if (courseStats.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No course data available</td></tr>';
            return;
        }

        tbody.innerHTML = courseStats.map(stat => `
            <tr>
                <td><strong>${stat.courseName}</strong></td>
                <td>${stat.totalEnrollments}</td>
                <td>${stat.completed}</td>
                <td>${stat.completionRate}%</td>
                <td><strong>${stat.averageScore}%</strong></td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Failed to load course stats:', error);
    }
}

function populateFilters() {
    const users = [...new Set(allProgressData.map(p => p.userId))];
    const courses = [...new Set(allProgressData.map(p => ({ id: p.courseId, name: p.courseName })))];

    document.getElementById('userFilter').innerHTML = 
        '<option value="all">All Users</option>' +
        users.map(user => `<option value="${user}">User ${user}</option>`).join('');

    document.getElementById('courseFilter').innerHTML = 
        '<option value="all">All Courses</option>' +
        courses.map(course => `<option value="${course.id}">${course.name}</option>`).join('');
}

function filterData() {
    const userFilter = document.getElementById('userFilter').value;
    const courseFilter = document.getElementById('courseFilter').value;

    let filteredData = allProgressData;
    if (userFilter !== 'all') filteredData = filteredData.filter(p => p.userId === userFilter);
    if (courseFilter !== 'all') filteredData = filteredData.filter(p => p.courseId === courseFilter);

    displayProgressData(filteredData);
}

function displayProgressData(data) {
    const tbody = document.getElementById('activityTableBody');

    if (data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No data available</td></tr>';
        return;
    }

    data.sort((a, b) => new Date(b.lastAccessed) - new Date(a.lastAccessed));

    tbody.innerHTML = data.map(item => {
        const statusClass = getStatusClass(item.lessonStatus);
        const statusText = item.displayStatus || item.lessonStatus || 'not attempted';
        
        return `
            <tr>
                <td><strong>User ${item.userId}</strong></td>
                <td>${item.courseName}</td>
                <td><span class="status-badge status-${statusClass}">${statusText}</span></td>
                <td>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${item.progressPercent}%"></div>
                    </div>
                    <span class="progress-text">${item.progressPercent}%</span>
                </td>
                <td><strong>${item.score !== null ? item.score + '%' : '-'}</strong></td>
                <td>${item.sessionTime || '00:00:00'}</td>
                <td>${formatDate(item.lastAccessed)}</td>
            </tr>
        `;
    }).join('');
}

function getStatusClass(status) {
    const statusMap = {
        'completed': 'completed',
        'passed': 'completed',
        'incomplete': 'in-progress',
        'failed': 'failed',
        'not attempted': 'not-started'
    };
    return statusMap[status?.toLowerCase()] || 'not-started';
}

function formatDate(dateString) {
    if (!dateString) return '-';
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} min ago`;
    if (diffHours < 24) return `${diffHours} hours ago`;
    if (diffDays < 7) return `${diffDays} days ago`;
    
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatTime(dateString) {
    if (!dateString) return '-';
    return new Date(dateString).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function logout() {
    TokenManager.clearTokens();
    window.location.href = '/login.html';
}
