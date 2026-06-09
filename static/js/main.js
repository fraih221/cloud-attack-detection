// ============================================================================
// CLOUD ATTACK DETECTION SYSTEM - MAIN JAVASCRIPT
// ============================================================================

// === GLOBAL VARIABLES ===
let currentUser = null;
let statsInterval = null;

// === DOM READY ===
document.addEventListener('DOMContentLoaded', function () {
    initializeApp();
});

// === INITIALIZATION ===
function initializeApp() {
    // Initialize mobile menu
    initMobileMenu();

    // Initialize tooltips
    initTooltips();

    // Initialize animations
    initAnimations();

    // Auto-refresh stats if on dashboard
    if (window.location.pathname.includes('dashboard')) {
        startStatsRefresh();
    }

    console.log('Cloud Attack Detection System initialized');
}

// === MOBILE MENU ===
function initMobileMenu() {
    const hamburger = document.querySelector('.hamburger');
    const navMenu = document.querySelector('.nav-menu');

    if (hamburger && navMenu) {
        hamburger.addEventListener('click', function () {
            navMenu.classList.toggle('active');
            hamburger.classList.toggle('active');
        });

        // Close menu when clicking outside
        document.addEventListener('click', function (event) {
            if (!hamburger.contains(event.target) && !navMenu.contains(event.target)) {
                navMenu.classList.remove('active');
                hamburger.classList.remove('active');
            }
        });
    }
}

// === TOOLTIPS ===
function initTooltips() {
    const tooltipElements = document.querySelectorAll('[data-tooltip]');

    tooltipElements.forEach(element => {
        element.addEventListener('mouseenter', function () {
            const tooltip = document.createElement('div');
            tooltip.className = 'tooltip';
            tooltip.textContent = this.getAttribute('data-tooltip');
            document.body.appendChild(tooltip);

            const rect = this.getBoundingClientRect();
            tooltip.style.top = rect.top - tooltip.offsetHeight - 10 + 'px';
            tooltip.style.left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2) + 'px';
        });

        element.addEventListener('mouseleave', function () {
            const tooltip = document.querySelector('.tooltip');
            if (tooltip) {
                tooltip.remove();
            }
        });
    });
}

// === ANIMATIONS ===
function initAnimations() {
    // Fade in elements on scroll
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver(function (entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in');
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    const animatedElements = document.querySelectorAll('.feature-card, .step, .stat-card');
    animatedElements.forEach(el => observer.observe(el));
}

// === STATS REFRESH ===
function startStatsRefresh() {
    // Refresh stats every 30 seconds
    statsInterval = setInterval(refreshStats, 30000);
}

async function refreshStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();

        if (data) {
            updateStatsDisplay(data);
        }
    } catch (error) {
        console.error('Error refreshing stats:', error);
    }
}

function updateStatsDisplay(stats) {
    const elements = {
        totalPredictions: document.querySelector('.stat-card:nth-child(1) h3'),
        attacksDetected: document.querySelector('.stat-card:nth-child(2) h3'),
        normalTraffic: document.querySelector('.stat-card:nth-child(3) h3'),
        accuracyRate: document.querySelector('.stat-card:nth-child(4) h3')
    };

    if (elements.totalPredictions) {
        elements.totalPredictions.textContent = stats.total_predictions || 0;
    }
    if (elements.attacksDetected) {
        elements.attacksDetected.textContent = stats.total_attacks_detected || 0;
    }
    if (elements.normalTraffic) {
        elements.normalTraffic.textContent = stats.total_normal_traffic || 0;
    }
    if (elements.accuracyRate) {
        elements.accuracyRate.textContent = (stats.accuracy_rate || 0).toFixed(2) + '%';
    }
}

// === FORM VALIDATION ===
function validateForm(formId) {
    const form = document.getElementById(formId);
    if (!form) return false;

    const inputs = form.querySelectorAll('input[required]');
    let isValid = true;

    inputs.forEach(input => {
        if (!input.value.trim()) {
            isValid = false;
            input.classList.add('error');
        } else {
            input.classList.remove('error');
        }
    });

    return isValid;
}

// === PREDICTION HELPERS ===
function showPredictionLoading() {
    const button = document.querySelector('button[type="submit"]');
    if (button) {
        button.disabled = true;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
    }
}

function hidePredictionLoading() {
    const button = document.querySelector('button[type="submit"]');
    if (button) {
        button.disabled = false;
        button.innerHTML = '<i class="fas fa-search"></i> Predict';
    }
}

// === API HELPERS ===
async function makeApiRequest(url, method = 'GET', data = null) {
    const options = {
        method: method,
        headers: {
            'Content-Type': 'application/json'
        }
    };

    if (data) {
        options.body = JSON.stringify(data);
    }

    try {
        const response = await fetch(url, options);
        return await response.json();
    } catch (error) {
        console.error('API request failed:', error);
        throw error;
    }
}

// === NOTIFICATION SYSTEM ===
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <i class="fas fa-${getNotificationIcon(type)}"></i>
        <span>${message}</span>
        <button onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;

    document.body.appendChild(notification);

    // Auto remove after 5 seconds
    setTimeout(() => {
        notification.classList.add('fade-out');
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

function getNotificationIcon(type) {
    const icons = {
        'success': 'check-circle',
        'error': 'exclamation-circle',
        'warning': 'exclamation-triangle',
        'info': 'info-circle'
    };
    return icons[type] || 'info-circle';
}

// === DATA EXPORT ===
function exportToCSV(data, filename) {
    const csv = convertToCSV(data);
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    window.URL.revokeObjectURL(url);
}

function convertToCSV(data) {
    if (!data || data.length === 0) return '';

    const headers = Object.keys(data[0]);
    const csvRows = [];

    // Add headers
    csvRows.push(headers.join(','));

    // Add data rows
    for (const row of data) {
        const values = headers.map(header => {
            const value = row[header];
            return typeof value === 'string' ? `"${value}"` : value;
        });
        csvRows.push(values.join(','));
    }

    return csvRows.join('\n');
}

// === CHART HELPERS ===
function createChart(canvasId, type, data, options = {}) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    return new Chart(ctx.getContext('2d'), {
        type: type,
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            ...options
        }
    });
}

// === REAL-TIME UPDATES ===
function startRealtimeUpdates() {
    // Fetch recent attacks every 10 seconds
    setInterval(async () => {
        try {
            const response = await fetch('/api/recent-attacks');
            const attacks = await response.json();
            updateAttacksList(attacks);
        } catch (error) {
            console.error('Error fetching recent attacks:', error);
        }
    }, 10000);
}

function updateAttacksList(attacks) {
    const tbody = document.querySelector('.attack-logs tbody');
    if (!tbody) return;

    tbody.innerHTML = '';

    attacks.forEach(attack => {
        const row = tbody.insertRow();
        row.innerHTML = `
            <td>#${attack.id}</td>
            <td>${attack.attack_type}</td>
            <td><span class="badge badge-${attack.severity.toLowerCase()}">${attack.severity}</span></td>
            <td>${attack.source_ip}</td>
            <td>${attack.destination_ip}</td>
            <td>${attack.protocol}</td>
            <td>${attack.detected_at}</td>
            <td><span class="badge badge-info">${attack.status}</span></td>
        `;
    });
}

// === UTILITY FUNCTIONS ===
function formatNumber(num) {
    return new Intl.NumberFormat().format(num);
}

function formatPercentage(num) {
    return (num * 100).toFixed(2) + '%';
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function throttle(func, limit) {
    let inThrottle;
    return function () {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// === SEARCH & FILTER ===
function filterTable(tableId, searchTerm) {
    const table = document.getElementById(tableId);
    if (!table) return;

    const rows = table.querySelectorAll('tbody tr');
    const term = searchTerm.toLowerCase();

    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(term) ? '' : 'none';
    });
}

// === LOCAL STORAGE ===
function saveToLocalStorage(key, value) {
    try {
        localStorage.setItem(key, JSON.stringify(value));
        return true;
    } catch (error) {
        console.error('Error saving to localStorage:', error);
        return false;
    }
}

function getFromLocalStorage(key) {
    try {
        const item = localStorage.getItem(key);
        return item ? JSON.parse(item) : null;
    } catch (error) {
        console.error('Error reading from localStorage:', error);
        return null;
    }
}

// === DARK MODE ===
function toggleDarkMode() {
    document.body.classList.toggle('dark-mode');
    const isDark = document.body.classList.contains('dark-mode');
    saveToLocalStorage('darkMode', isDark);
}

function initDarkMode() {
    const isDark = getFromLocalStorage('darkMode');
    if (isDark) {
        document.body.classList.add('dark-mode');
    }
}

// === COPY TO CLIPBOARD ===
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showNotification('Copied to clipboard!', 'success');
    }).catch(err => {
        console.error('Failed to copy:', err);
        showNotification('Failed to copy', 'error');
    });
}

// === PRINT ===
function printPage() {
    window.print();
}

// === DOWNLOAD ===
function downloadFile(url, filename) {
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

// === CONFIRMATION DIALOG ===
function confirmAction(message, callback) {
    if (confirm(message)) {
        callback();
    }
}

// === LOADING SPINNER ===
function showLoadingSpinner() {
    const spinner = document.createElement('div');
    spinner.id = 'loading-spinner';
    spinner.className = 'loading-spinner';
    spinner.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
    document.body.appendChild(spinner);
}

function hideLoadingSpinner() {
    const spinner = document.getElementById('loading-spinner');
    if (spinner) {
        spinner.remove();
    }
}

// === FORM RESET ===
function resetForm(formId) {
    const form = document.getElementById(formId);
    if (form) {
        form.reset();
        // Remove error classes
        const inputs = form.querySelectorAll('.error');
        inputs.forEach(input => input.classList.remove('error'));
    }
}

// === AUTO-SAVE ===
let autoSaveTimeout;
function autoSave(formId, key) {
    clearTimeout(autoSaveTimeout);
    autoSaveTimeout = setTimeout(() => {
        const form = document.getElementById(formId);
        if (form) {
            const formData = new FormData(form);
            const data = Object.fromEntries(formData);
            saveToLocalStorage(key, data);
            showNotification('Auto-saved', 'info');
        }
    }, 2000);
}

// === KEYBOARD SHORTCUTS ===
document.addEventListener('keydown', function (e) {
    // Ctrl+S to save
    if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        const form = document.querySelector('form');
        if (form) {
            form.dispatchEvent(new Event('submit'));
        }
    }

    // Escape to close modals
    if (e.key === 'Escape') {
        const modals = document.querySelectorAll('.modal.active');
        modals.forEach(modal => modal.classList.remove('active'));
    }
});

// === SCROLL TO TOP ===
function scrollToTop() {
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
}

// Show scroll to top button
window.addEventListener('scroll', function () {
    const scrollBtn = document.getElementById('scroll-to-top');
    if (scrollBtn) {
        if (window.pageYOffset > 300) {
            scrollBtn.style.display = 'block';
        } else {
            scrollBtn.style.display = 'none';
        }
    }
});

// === CLEANUP ===
window.addEventListener('beforeunload', function () {
    // Clear intervals
    if (statsInterval) {
        clearInterval(statsInterval);
    }
});

// === EXPORT FUNCTIONS ===
window.CloudAttackDetection = {
    showNotification,
    exportToCSV,
    createChart,
    filterTable,
    toggleDarkMode,
    copyToClipboard,
    printPage,
    downloadFile,
    confirmAction,
    showLoadingSpinner,
    hideLoadingSpinner,
    scrollToTop
};

console.log('Cloud Attack Detection System - JavaScript loaded successfully');
