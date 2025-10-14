// Google Analytics 4 Implementation
(function() {
    'use strict';

    // Your actual Measurement ID
    const GA_MEASUREMENT_ID = 'G-TXW2PGKF86';

    // Load Google Analytics
    function loadGoogleAnalytics() {
        // Create script tag for gtag.js
        const script = document.createElement('script');
        script.async = true;
        script.src = `https://www.googletagmanager.com/gtag/js?id=${GA_MEASUREMENT_ID}`;
        document.head.appendChild(script);

        // Initialize gtag
        window.dataLayer = window.dataLayer || [];
        function gtag(){dataLayer.push(arguments);}
        gtag('js', new Date());
        gtag('config', GA_MEASUREMENT_ID, {
            'send_page_view': true
        });

        window.gtag = gtag;
        console.log('✅ Google Analytics loaded:', GA_MEASUREMENT_ID);
    }

    // Track custom events
    window.trackEvent = function(eventName, eventParams) {
        if (window.gtag) {
            window.gtag('event', eventName, eventParams);
            console.log('📊 GA Event:', eventName, eventParams);
        }
    };

    // Track page views (for SPAs)
    window.trackPageView = function(pagePath, pageTitle) {
        if (window.gtag) {
            window.gtag('event', 'page_view', {
                page_path: pagePath,
                page_title: pageTitle
            });
            console.log('📊 GA Page View:', pagePath, pageTitle);
        }
    };

    // Load on page load
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', loadGoogleAnalytics);
    } else {
        loadGoogleAnalytics();
    }
})();