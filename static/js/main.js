// Secure File Sharing System - Interactive JS

document.addEventListener('DOMContentLoaded', function () {

    // ── Bootstrap Tooltips ──────────────────────────────────────────────
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // ── Auto-dismiss alerts after 6 seconds ────────────────────────────
    setTimeout(function () {
        var alerts = document.querySelectorAll('.alert-dismissible');
        alerts.forEach(function (alert) {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 6000);

    // ── Mobile Sidebar Toggle ──────────────────────────────────────────
    var sidebarToggleBtn = document.getElementById('sidebarToggle');
    var sidebar          = document.getElementById('mainSidebar');
    var backdrop         = document.getElementById('sidebarBackdrop');

    function openSidebar() {
        if (!sidebar) return;
        sidebar.classList.add('sidebar-open');
        if (backdrop) backdrop.classList.add('show');
        document.body.style.overflow = 'hidden'; // prevent scroll behind drawer
    }

    function closeSidebar() {
        if (!sidebar) return;
        sidebar.classList.remove('sidebar-open');
        if (backdrop) backdrop.classList.remove('show');
        document.body.style.overflow = '';
    }

    function isMobile() {
        return window.innerWidth < 992;
    }

    // Hamburger button click
    if (sidebarToggleBtn) {
        sidebarToggleBtn.addEventListener('click', function (e) {
            e.stopPropagation();
            if (sidebar && sidebar.classList.contains('sidebar-open')) {
                closeSidebar();
            } else {
                openSidebar();
            }
        });
    }

    // Backdrop click closes sidebar
    if (backdrop) {
        backdrop.addEventListener('click', closeSidebar);
    }

    // Swipe-left on sidebar to close (touch support)
    if (sidebar) {
        var touchStartX = null;
        sidebar.addEventListener('touchstart', function (e) {
            touchStartX = e.touches[0].clientX;
        }, { passive: true });

        sidebar.addEventListener('touchend', function (e) {
            if (touchStartX === null) return;
            var diff = touchStartX - e.changedTouches[0].clientX;
            if (diff > 60) { // swiped left ≥ 60px
                closeSidebar();
            }
            touchStartX = null;
        }, { passive: true });
    }

    // Close sidebar on nav-link click (mobile UX — navigate & auto-close)
    if (sidebar) {
        var navLinks = sidebar.querySelectorAll('.sidebar-link');
        navLinks.forEach(function (link) {
            link.addEventListener('click', function () {
                if (isMobile()) {
                    closeSidebar();
                }
            });
        });
    }

    // On resize back to desktop — remove inline overflow and open state
    window.addEventListener('resize', function () {
        if (!isMobile()) {
            closeSidebar();
        }
    });

});

// Clipboard Helper
function copyToClipboard(text, buttonElement) {
    if (!navigator.clipboard) {
        var textArea = document.createElement("textarea");
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        try {
            document.execCommand('copy');
            showCopySuccess(buttonElement);
        } catch (err) {
            console.error('Copy fallback failed', err);
        }
        document.body.removeChild(textArea);
        return;
    }

    navigator.clipboard.writeText(text).then(function () {
        showCopySuccess(buttonElement);
    }).catch(function (err) {
        console.error('Failed to copy: ', err);
    });
}

function showCopySuccess(btn) {
    if (!btn) return;
    var originalHtml = btn.innerHTML;
    btn.innerHTML = '<i class="bi bi-check-lg"></i> Copied!';
    btn.classList.add('btn-success');
    setTimeout(function () {
        btn.innerHTML = originalHtml;
        btn.classList.remove('btn-success');
    }, 2000);
}
