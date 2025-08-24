// Main Application JavaScript
document.addEventListener('DOMContentLoaded', function() {
    
    // Initialize tooltips if Bootstrap is available
    if (typeof bootstrap !== 'undefined') {
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }
    
    // File input styling enhancement
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
        input.addEventListener('change', function(e) {
            const fileName = e.target.files[0]?.name || 'Choose file...';
            const label = e.target.parentNode.querySelector('.file-label');
            if (label) {
                label.textContent = fileName;
            }
        });
    });
    
    // Form validation enhancement
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.classList.add('loading');
                submitBtn.disabled = true;
                
                // Re-enable after 5 seconds as fallback
                setTimeout(() => {
                    submitBtn.classList.remove('loading');
                    submitBtn.disabled = false;
                }, 5000);
            }
        });
    });
    
    // Smooth scroll for anchor links
    const anchorLinks = document.querySelectorAll('a[href^="#"]');
    anchorLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
    
    // Auto-hide alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
    alerts.forEach(alert => {
        setTimeout(() => {
            if (alert.parentNode) {
                alert.style.opacity = '0';
                alert.style.transform = 'translateY(-20px)';
                setTimeout(() => {
                    if (alert.parentNode) {
                        alert.remove();
                    }
                }, 300);
            }
        }, 5000);
    });
    
    // Job status polling for brute force operations
    const jobElements = document.querySelectorAll('[data-job-id]');
    if (jobElements.length > 0) {
        startJobPolling();
    }
    
    // Add glow effect to buttons on hover
    const glowButtons = document.querySelectorAll('.btn-glow');
    glowButtons.forEach(btn => {
        btn.addEventListener('mouseenter', function() {
            this.style.boxShadow = '0 0 25px rgba(0, 255, 102, 0.6)';
        });
        
        btn.addEventListener('mouseleave', function() {
            this.style.boxShadow = '0 0 15px rgba(0, 255, 102, 0.3)';
        });
    });
    
    // Copy to clipboard functionality
    const copyButtons = document.querySelectorAll('[data-clipboard]');
    copyButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const text = this.getAttribute('data-clipboard');
            navigator.clipboard.writeText(text).then(() => {
                showToast('Copied to clipboard!', 'success');
            }).catch(() => {
                showToast('Failed to copy', 'error');
            });
        });
    });
    
    // Password strength indicator
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    passwordInputs.forEach(input => {
        if (input.name === 'password' && !input.hasAttribute('data-no-strength')) {
            addPasswordStrengthIndicator(input);
        }
    });
});

// Job status polling
function startJobPolling() {
    const jobElements = document.querySelectorAll('[data-job-id]');
    
    jobElements.forEach(element => {
        const jobId = element.getAttribute('data-job-id');
        pollJobStatus(jobId);
    });
}

function pollJobStatus(jobId) {
    const pollInterval = setInterval(() => {
        fetch(`/job/status/${jobId}`)
            .then(response => response.json())
            .then(data => {
                updateJobStatus(jobId, data);
                
                if (data.status === 'completed' || data.status === 'failed' || data.status === 'cancelled') {
                    clearInterval(pollInterval);
                }
            })
            .catch(error => {
                console.error('Error polling job status:', error);
                clearInterval(pollInterval);
            });
    }, 2000);
}

function updateJobStatus(jobId, data) {
    const element = document.querySelector(`[data-job-id="${jobId}"]`);
    if (!element) return;
    
    const statusElement = element.querySelector('.job-status');
    const progressElement = element.querySelector('.job-progress');
    const resultElement = element.querySelector('.job-result');
    
    if (statusElement) {
        statusElement.textContent = data.status;
        statusElement.className = `job-status badge bg-${getStatusColor(data.status)}`;
    }
    
    if (progressElement && data.progress !== undefined) {
        progressElement.style.width = `${data.progress}%`;
        progressElement.setAttribute('aria-valuenow', data.progress);
    }
    
    if (resultElement && data.result) {
        resultElement.textContent = data.result;
        resultElement.style.display = 'block';
    }
}

function getStatusColor(status) {
    switch (status) {
        case 'completed': return 'success';
        case 'failed': return 'danger';
        case 'cancelled': return 'secondary';
        case 'running': return 'warning';
        default: return 'primary';
    }
}

// Toast notifications
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast-notification toast-${type}`;
    toast.innerHTML = `
        <div class="toast-content">
            <i class="fas fa-${getToastIcon(type)}"></i>
            <span>${message}</span>
        </div>
        <button class="toast-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    document.body.appendChild(toast);
    
    // Trigger animation
    setTimeout(() => toast.classList.add('show'), 100);
    
    // Auto-remove after 4 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => {
            if (toast.parentNode) {
                toast.remove();
            }
        }, 300);
    }, 4000);
}

function getToastIcon(type) {
    switch (type) {
        case 'success': return 'check-circle';
        case 'error': return 'exclamation-circle';
        case 'warning': return 'exclamation-triangle';
        default: return 'info-circle';
    }
}

// Password strength indicator
function addPasswordStrengthIndicator(input) {
    const container = document.createElement('div');
    container.className = 'password-strength';
    container.innerHTML = `
        <div class="strength-meter">
            <div class="strength-fill"></div>
        </div>
        <small class="strength-text">Password strength: <span>Weak</span></small>
    `;
    
    input.parentNode.appendChild(container);
    
    input.addEventListener('input', function() {
        const strength = calculatePasswordStrength(this.value);
        updatePasswordStrength(container, strength);
    });
}

function calculatePasswordStrength(password) {
    let score = 0;
    
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    
    return Math.min(score, 5);
}

function updatePasswordStrength(container, strength) {
    const fill = container.querySelector('.strength-fill');
    const text = container.querySelector('.strength-text span');
    
    const strengthLevels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong'];
    const strengthColors = ['#ff4444', '#ff6b4a', '#ffa500', '#ffd700', '#90ee90', '#00ff66'];
    
    const level = Math.max(0, strength - 1);
    const percentage = (strength / 5) * 100;
    
    fill.style.width = `${percentage}%`;
    fill.style.backgroundColor = strengthColors[level];
    text.textContent = strengthLevels[level];
    text.style.color = strengthColors[level];
}

// Utility functions
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
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

// Error handling for matrix canvas
window.addEventListener('error', function(e) {
    if (e.filename && e.filename.includes('matrix.js')) {
        console.warn('Matrix effect encountered an error, continuing without it.');
        const canvas = document.getElementById('matrix-canvas');
        if (canvas) {
            canvas.style.display = 'none';
        }
    }
});

// Performance monitoring
if ('performance' in window) {
    window.addEventListener('load', function() {
        setTimeout(() => {
            const perfData = window.performance.timing;
            const loadTime = perfData.loadEventEnd - perfData.navigationStart;
            
            if (loadTime > 3000) {
                console.warn('Page load time exceeded 3 seconds:', loadTime + 'ms');
            }
        }, 0);
    });
}
