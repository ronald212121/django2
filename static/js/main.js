// Inisialisasi komponen-komponen interaktif setelah DOM selesai dimuat
document.addEventListener('DOMContentLoaded', function() {
    // Animasi progress circle untuk skor vulnerability
    animateProgressCircles();
    
    // Tambahkan event listener untuk form scanning
    setupScanningForms();
    
    // Aktifkan tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Efek hover pada card
    setupCardHoverEffects();
    
    // Copy to clipboard functionality
    setupClipboardCopy();
    
    // Setup real-time form validation
    setupFormValidation();
});

// Animasi progress circle untuk menampilkan skor vulnerability
function animateProgressCircles() {
    const circles = document.querySelectorAll('.progress-circle');
    
    circles.forEach(circle => {
        const score = parseInt(circle.getAttribute('data-score'));
        const scoreElement = circle.querySelector('.score-value');
        const scoreBg = circle.querySelector('.score-bg');
        
        // Tentukan kelas berdasarkan skor
        if (score < 40) {
            circle.classList.add('score-critical');
        } else if (score < 60) {
            circle.classList.add('score-high');
        } else if (score < 75) {
            circle.classList.add('score-medium');
        } else {
            circle.classList.add('score-low');
        }
        
        // Animasi skor dari 0 ke nilai sebenarnya
        let currentScore = 0;
        const targetScore = score;
        const duration = 1500; // durasi animasi dalam ms
        const interval = 10; // interval update dalam ms
        const steps = duration / interval;
        const increment = targetScore / steps;
        
        const counter = setInterval(() => {
            currentScore += increment;
            
            if (currentScore >= targetScore) {
                currentScore = targetScore;
                clearInterval(counter);
            }
            
            // Update nilai yang ditampilkan
            if (scoreElement) {
                scoreElement.textContent = Math.round(currentScore);
            }
            
            // Update latar belakang conic-gradient
            if (scoreBg) {
                const angle = (currentScore / 100) * 360;
                scoreBg.style.background = `conic-gradient(
                    ${getScoreColor(currentScore)} 0deg ${angle}deg,
                    #f3f3f3 ${angle}deg 360deg
                )`;
            }
        }, interval);
    });
}

// Tentukan warna berdasarkan skor
function getScoreColor(score) {
    if (score < 40) {
        return '#e74c3c'; // Merah untuk skor rendah (kritis)
    } else if (score < 60) {
        return '#ff7043'; // Oranye untuk skor medium-rendah (tinggi)
    } else if (score < 75) {
        return '#f39c12'; // Kuning untuk skor medium (sedang)
    } else {
        return '#2ecc71'; // Hijau untuk skor tinggi (rendah)
    }
}

// Setup form scanning dengan validasi dan animasi loading
function setupScanningForms() {
    const scanForms = document.querySelectorAll('.scan-form');
    
    scanForms.forEach(form => {
        form.addEventListener('submit', function(e) {
            // Validasi input
            const targetInput = form.querySelector('input[name="target"]');
            if (!targetInput.value.trim()) {
                e.preventDefault();
                showAlert('Target tidak boleh kosong!', 'danger');
                return;
            }
            
            // Tampilkan animasi loading
            showLoadingSpinner('Scanning in progress... This may take a few minutes.');
        });
    });
}

// Tampilkan loading spinner
function showLoadingSpinner(message) {
    const spinnerOverlay = document.createElement('div');
    spinnerOverlay.className = 'spinner-overlay';
    spinnerOverlay.innerHTML = `
        <div class="text-center">
            <div class="spinner-border text-light" style="width: 3rem; height: 3rem;" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <div class="spinner-text">${message || 'Loading...'}</div>
        </div>
    `;
    
    document.body.appendChild(spinnerOverlay);
    
    // Auto-remove after timeout (as a fallback)
    setTimeout(() => {
        const existingOverlay = document.querySelector('.spinner-overlay');
        if (existingOverlay) {
            existingOverlay.remove();
        }
    }, 60000); // 60 seconds timeout
}

// Hilangkan loading spinner
function hideLoadingSpinner() {
    const existingOverlay = document.querySelector('.spinner-overlay');
    if (existingOverlay) {
        existingOverlay.remove();
    }
}

// Tampilkan pesan alert
function showAlert(message, type = 'info') {
    const alertPlaceholder = document.getElementById('alert-placeholder');
    if (!alertPlaceholder) return;
    
    const wrapper = document.createElement('div');
    wrapper.innerHTML = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    `;
    
    alertPlaceholder.append(wrapper);
    
    // Auto dismiss after 5 seconds
    setTimeout(() => {
        const alert = bootstrap.Alert.getInstance(wrapper.querySelector('.alert'));
        if (alert) {
            alert.close();
        }
    }, 5000);
}

// Efek hover pada cards
function setupCardHoverEffects() {
    const cards = document.querySelectorAll('.card');
    
    cards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-10px)';
            this.style.boxShadow = '0 15px 30px rgba(0, 0, 0, 0.15)';
            this.style.transition = 'all 0.3s ease';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
            this.style.boxShadow = '0 5px 15px rgba(0, 0, 0, 0.1)';
        });
    });
}

// Fungsi untuk menyalin teks ke clipboard
function setupClipboardCopy() {
    const copyButtons = document.querySelectorAll('.copy-btn');
    
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const textToCopy = this.getAttribute('data-copy');
            const textarea = document.createElement('textarea');
            textarea.value = textToCopy;
            textarea.style.position = 'fixed';
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            
            // Ubah label button untuk konfirmasi
            const originalText = this.innerHTML;
            this.innerHTML = '<i class="fas fa-check"></i> Copied!';
            
            setTimeout(() => {
                this.innerHTML = originalText;
            }, 2000);
        });
    });
}

// Form validation setup
function setupFormValidation() {
    const forms = document.querySelectorAll('.needs-validation');
    
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            
            form.classList.add('was-validated');
        }, false);
    });
}

// Konfirmasi sebelum menghapus scan result atau history
function confirmDelete(message) {
    return confirm(message || 'Apakah Anda yakin ingin menghapus item ini?');
}

// Export function untuk hasil pemindaian
function exportToCSV(tableId, filename) {
    const table = document.getElementById(tableId);
    if (!table) return;
    
    let csv = [];
    const rows = table.querySelectorAll('tr');
    
    for (let i = 0; i < rows.length; i++) {
        let row = [], cols = rows[i].querySelectorAll('td, th');
        
        for (let j = 0; j < cols.length; j++) {
            // Replace double quotes with two double quotes
            let text = cols[j].innerText.replace(/"/g, '""');
            // Add quoted text to the row
            row.push('"' + text + '"');
        }
        
        csv.push(row.join(','));
    }
    
    // Download CSV file
    downloadCSV(csv.join('\n'), filename);
}

function downloadCSV(csv, filename) {
    const csvFile = new Blob([csv], {type: 'text/csv'});
    const downloadLink = document.createElement('a');
    
    // File name
    downloadLink.download = filename || 'export.csv';
    
    // Create a link to the file
    downloadLink.href = window.URL.createObjectURL(csvFile);
    
    // Hide download link
    downloadLink.style.display = 'none';
    
    // Add the link to DOM
    document.body.appendChild(downloadLink);
    
    // Click download link
    downloadLink.click();
    
    // Clean up
    document.body.removeChild(downloadLink);
}