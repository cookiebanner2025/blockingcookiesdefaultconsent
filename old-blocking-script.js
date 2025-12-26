/* ============================================================
   COOKIE BLOCKING FIREWALL - INTEGRATED WITH CUSTOM BANNER
   This blocks all cookies and trackers BEFORE consent is given
============================================================ */
/* ============================================================
   ENHANCED COOKIE BLOCKING FIREWALL WITH CATEGORY SUPPORT
/* ============================================================
   FIXED COOKIE BLOCKING FIREWALL WITH CATEGORY SUPPORT
============================================================ */
(function () {
    'use strict';

     
    /* ===================== CONFIGURATION ===================== */
   // Use global settings
    const BLOCKING_ENABLED = window.COOKIE_SETTINGS.BLOCKING_ENABLED;
    const RELOAD_ENABLED = window.COOKIE_SETTINGS.RELOAD_ENABLED;
   
    const CONSENT_KEY = "__user_cookie_consent__";
    const CATEGORIES_KEY = "__user_cookie_categories__";
    
    // Get stored consent data
    const storedConsent = localStorage.getItem(CONSENT_KEY);
    const storedCategories = localStorage.getItem(CATEGORIES_KEY);
    
    console.log("🛡️ Blocking Script Initialized");
    console.log("Consent Status:", storedConsent);
    console.log("Categories:", storedCategories);
    
    /* ===================== EXIT CONDITIONS ===================== */
    // If user gave FULL consent, don't block anything
    if (storedConsent === "granted") {
        console.info("✅ Full consent granted – all tracking allowed");
        return; // Exit the blocking script
    }



           /* ===================== BLOCKING ON/OFF SWITCH ===================== */
    // ADD THESE NEW LINES HERE:
    // If blocking is disabled, exit the entire script
    if (!BLOCKING_ENABLED) {
        console.log("🟡 Blocking feature is OFF - all tracking allowed");
        return; // Exit without blocking anything
    }

   
    // If user gave FULL consent, don't block anything
    if (storedConsent === "granted") {
        console.info("✅ Full consent granted – all tracking allowed");
        return; // Exit the blocking script
    }
    // If user gave PARTIAL consent (custom categories), we'll block selectively
    // If no consent at all, block everything
    
    /* ===================== CATEGORY DEFINITIONS ===================== */
    // These domains and cookies will be blocked UNLESS user consents to their category
    
    // ANALYTICS DOMAINS & COOKIES
    const ANALYTICS_DATA = {
        domains: [
            // Google Analytics
          "google-analytics.com", "www.google-analytics.com", "analytics.google.com",
            // Microsoft Clarity
            "clarity.ms", "www.clarity.ms",
            // Hotjar
            "hotjar.com", "insights.hotjar.com",
            // Other analytics
            "segment.com", "cdn.segment.com",
            "mixpanel.com", "api.mixpanel.com",
            "heap.io", "cdn.heap.io",
            "fullstory.com", "rs.fullstory.com",
            "mouseflow.com", "cdn.mouseflow.com",
            "logrocket.com", "cdn.logrocket.com"
        ],
        cookies: [
            // Google Analytics
            "_ga", "_gid", "_gat", "_ga_", "_gat_UA-", "_gat_gtag", "_dc_gtm_",
            // Microsoft Clarity
            "_clck", "_clsk", "_cltk", "CLID", "ANONCHK", "SM",
            // Hotjar
            "_hjid", "_hjIncludedInPageviewSample", "_hjClosedSurveyInvites",
            "_hjDonePolls", "_hjMinimizedPolls", "_hjShownFeedbackMessage",
            // HubSpot
            "hubspotutk", "__hssc", "__hssrc", "__hstc", "hsfirstvisit",
            // Matomo
            "_pk_id", "_pk_ses",
            // Segment
            "ajs_anonymous_id", "ajs_user_id"
        ]
    };
    
    // MARKETING/ADVERTISING DOMAINS & COOKIES
    const MARKETING_DATA = {
        domains: [
            // Google Ads
            "googleadservices.com", "www.googleadservices.com", "doubleclick.net",
            "www.doubleclick.net", "googlesyndication.com",
            // Facebook/Meta
            "facebook.com", "www.facebook.com", "connect.facebook.net",
            "fbcdn.net", "fbsbx.com",
            // Microsoft Ads
            "bing.com", "bat.bing.com",
            // TikTok
            "tiktok.com", "analytics.tiktok.com", "ads.tiktok.com",
            // LinkedIn
            "linkedin.com", "www.linkedin.com", "snap.licdn.com",
            // Pinterest
            "pinterest.com", "www.pinterest.com",
            // Other ad networks
            "criteo.com", "adsrvr.org", "rubiconproject.com",
            "amazon-adsystem.com", "outbrain.com", "taboola.com"
        ],
        cookies: [
            // Google Ads
            "_gcl", "_gcl_au", "gclid", "IDE", "NID", "DSID", "FPLC",
            "1P_JAR", "CONSENT", "AEC", "__Secure-3PAPISID",
            // Facebook
            "_fbp", "_fbc", "fr", "xs", "c_user", "datr", "sb",
            // Microsoft Ads
            "_uetvid", "_uetsid", "_uetmsclkid", "MUID", "MUIDB",
            // TikTok
            "_ttp", "ttclid", "tt_sessionid",
            // LinkedIn
            "lidc", "bcookie", "li_sugr", "bscookie",
            // Criteo
            "criteo", "uid"
        ]
    };
    
    // PERFORMANCE DOMAINS & COOKIES
    const PERFORMANCE_DATA = {
        domains: [
            "cloudflare.com", "cdn.cloudflare.com",
            "akamaihd.net", "edgekey.net"
        ],
        cookies: [
            "__cfduid", "__cf_bm", "AWSALB", "AWSALBCORS"
        ]
    };
    
    // ESSENTIAL DOMAINS & COOKIES (ALWAYS ALLOWED)
    const ESSENTIAL_DATA = {
        domains: [
            window.location.hostname,
            "cdnjs.cloudflare.com", "ajax.googleapis.com",
            "fonts.googleapis.com", "fonts.gstatic.com",
            "maps.googleapis.com", "stripe.com", "paypal.com"
        ],
        cookies: [
            "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId",
            "wordpress_logged_in_", "wordpress_sec_", "wp-settings-",
            "wp-settings-time-", "wordpress_test_cookie",
            "cookie_consent", "__user_cookie_consent__", "__user_cookie_categories__",
            "cart_token", "cart_items", "checkout_token",
            "woocommerce_cart_hash", "woocommerce_items_in_cart",
            "csrftoken", "XSRF-TOKEN", "_csrf"
        ]
    };
    
    /* ===================== HELPER FUNCTIONS ===================== */
    
    function getCategoryConsent(category) {
        if (!storedCategories) return false;
        
        try {
            const categories = JSON.parse(storedCategories);
            return categories[category] === true;
        } catch (e) {
            console.error("Error parsing categories:", e);
            return false;
        }
    }
    
    function shouldBlockDomain(url) {
        if (!url || typeof url !== 'string') return false;
        
        // Check if it's an essential domain (NEVER block)
        for (const domain of ESSENTIAL_DATA.domains) {
            if (url.includes(domain)) return false;
        }
        
        // Check analytics domains
        if (!getCategoryConsent('analytics')) {
            for (const domain of ANALYTICS_DATA.domains) {
                if (url.includes(domain)) {
                    console.log(`🛡️ Blocked Analytics Domain: ${url}`);
                    return true;
                }
            }
        }
        
        // Check marketing domains
        if (!getCategoryConsent('advertising')) {
            for (const domain of MARKETING_DATA.domains) {
                if (url.includes(domain)) {
                    console.log(`🛡️ Blocked Marketing Domain: ${url}`);
                    return true;
                }
            }
        }
        
        // Check performance domains
        if (!getCategoryConsent('performance')) {
            for (const domain of PERFORMANCE_DATA.domains) {
                if (url.includes(domain)) {
                    console.log(`🛡️ Blocked Performance Domain: ${url}`);
                    return true;
                }
            }
        }
        
        return false;
    }
    
    function shouldBlockCookie(cookieName) {
        if (!cookieName) return false;
        
        // Check if it's an essential cookie (NEVER block)
        for (const cookie of ESSENTIAL_DATA.cookies) {
            if (cookieName.includes(cookie) || cookie.includes(cookieName)) {
                return false;
            }
        }
        
        // Check analytics cookies
        if (!getCategoryConsent('analytics')) {
            for (const cookie of ANALYTICS_DATA.cookies) {
                if (cookieName.includes(cookie) || cookie.includes(cookieName)) {
                    console.log(`🛡️ Blocked Analytics Cookie: ${cookieName}`);
                    return true;
                }
            }
        }
        
        // Check marketing cookies
        if (!getCategoryConsent('advertising')) {
            for (const cookie of MARKETING_DATA.cookies) {
                if (cookieName.includes(cookie) || cookie.includes(cookieName)) {
                    console.log(`🛡️ Blocked Marketing Cookie: ${cookieName}`);
                    return true;
                }
            }
        }
        
        // Check performance cookies
        if (!getCategoryConsent('performance')) {
            for (const cookie of PERFORMANCE_DATA.cookies) {
                if (cookieName.includes(cookie) || cookie.includes(cookieName)) {
                    console.log(`🛡️ Blocked Performance Cookie: ${cookieName}`);
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /* ===================== IMPLEMENT BLOCKING ===================== */
    
    // 1. Block script loading
    const originalCreateElement = document.createElement;
    document.createElement = function (tagName) {
        const element = originalCreateElement.call(document, tagName);
        
        if (tagName.toLowerCase() === 'script') {
            const originalSetAttribute = element.setAttribute;
            
            element.setAttribute = function (name, value) {
                if (name === 'src' && shouldBlockDomain(value)) {
                    console.log(`🛡️ Blocked script loading: ${value}`);
                    return; // Don't set the src attribute
                }
                return originalSetAttribute.call(this, name, value);
            };
            
            Object.defineProperty(element, 'src', {
                set(value) {
                    if (shouldBlockDomain(value)) {
                        console.log(`🛡️ Blocked script src: ${value}`);
                        return;
                    }
                    this.setAttribute('src', value);
                },
                get() {
                    return this.getAttribute('src');
                }
            });
        }
        
        return element;
    };
    
    // 2. Block fetch requests
    if (window.fetch) {
        const originalFetch = window.fetch;
        window.fetch = function (resource, init) {
            const url = typeof resource === 'string' ? resource : resource.url;
            
            if (shouldBlockDomain(url)) {
                console.log(`🛡️ Blocked fetch request: ${url}`);
                return Promise.reject(new Error('Request blocked by cookie consent'));
            }
            
            return originalFetch.call(this, resource, init);
        };
    }
    
    // 3. Block XMLHttpRequest
    if (window.XMLHttpRequest) {
        const originalOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function (method, url) {
            if (shouldBlockDomain(url)) {
                console.log(`🛡️ Blocked XHR request: ${url}`);
                this._blocked = true;
                return;
            }
            return originalOpen.apply(this, arguments);
        };
        
        const originalSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function (body) {
            if (this._blocked) {
                console.log(`🛡️ Blocked XHR send`);
                return;
            }
            return originalSend.apply(this, arguments);
        };
    }
    
    // 4. Block iframes
    const observer = new MutationObserver(function (mutations) {
        mutations.forEach(function (mutation) {
            mutation.addedNodes.forEach(function (node) {
                if (node.nodeName === 'IFRAME' && node.src && shouldBlockDomain(node.src)) {
                    console.log(`🛡️ Blocked iframe: ${node.src}`);
                    node.parentNode.removeChild(node);
                }
            });
        });
    });
    
    observer.observe(document.documentElement, {
        childList: true,
        subtree: true
    });
    
    // 5. Block and delete cookies
    function blockAndDeleteCookies() {
        document.cookie.split(';').forEach(function (cookie) {
            const [name] = cookie.trim().split('=');
            if (name && shouldBlockCookie(name)) {
                // Delete the cookie
                document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; domain=${window.location.hostname}`;
                document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/;`;
                console.log(`🛡️ Deleted blocked cookie: ${name}`);
            }
        });
    }
    
    // Run immediately and set interval
    blockAndDeleteCookies();
    setInterval(blockAndDeleteCookies, 1000);
    
    // 6. Block inline tracking scripts
    function blockInlineTrackers() {
        document.querySelectorAll('script:not([src])').forEach(function (script) {
            const content = script.textContent || script.innerText;
            if (content) {
                // Check if it contains tracking code
                if (content.includes('google-analytics') || 
                    content.includes('gtag') || 
                    content.includes('dataLayer') || 
                    content.includes('fbq') ||
                    content.includes('clarity') ||
                    content.includes('hotjar')) {
                    
                    // Check if user has consented to the relevant category
                    const isAnalyticsCode = content.includes('google-analytics') || 
                                           content.includes('gtag') || 
                                           content.includes('clarity') ||
                                           content.includes('hotjar');
                    const isMarketingCode = content.includes('fbq') || 
                                           content.includes('facebook');
                    
                    if ((isAnalyticsCode && !getCategoryConsent('analytics')) ||
                        (isMarketingCode && !getCategoryConsent('advertising'))) {
                        console.log('🛡️ Blocked inline tracker script');
                        script.remove();
                    }
                }
            }
        });
    }
    
    blockInlineTrackers();
    new MutationObserver(blockInlineTrackers).observe(document.documentElement, {
        childList: true,
        subtree: true
    });
    
    console.log("🛡️ Cookie blocking initialized with current preferences");
    console.log("Analytics allowed:", getCategoryConsent('analytics'));
    console.log("Marketing allowed:", getCategoryConsent('advertising'));
    console.log("Performance allowed:", getCategoryConsent('performance'));
    
    /* ===================== HOOKS FOR YOUR BANNER ===================== */
    
    // Your banner will call these functions when user makes a choice
    
    window.enableAllTracking = function() {
        console.log("✅ Enabling ALL tracking");
        localStorage.setItem(CONSENT_KEY, "granted");
        localStorage.setItem(CATEGORIES_KEY, JSON.stringify({
            analytics: true,
            advertising: true,
            performance: true
        }));
        
// Only reload if reload feature is enabled
if (window.COOKIE_SETTINGS && window.COOKIE_SETTINGS.RELOAD_ENABLED) {
    setTimeout(() => {
        window.location.reload();
    }, 300);
} else {
    console.log("🟡 Page reload disabled - changes applied without refresh");
}
    };

   
   
    
    window.enableTrackingByCategory = function(categories) {
        console.log("✅ Enabling tracking for categories:", categories);
        
        // Store categories
        localStorage.setItem(CATEGORIES_KEY, JSON.stringify(categories));
        
        // Check if all categories are enabled
        const allEnabled = categories.analytics && 
                          categories.advertising && 
                          categories.performance;
        
        if (allEnabled) {
            localStorage.setItem(CONSENT_KEY, "granted");
        } else {
            localStorage.setItem(CONSENT_KEY, "partial");
        }
        
// Only reload if reload feature is enabled
if (window.COOKIE_SETTINGS && window.COOKIE_SETTINGS.RELOAD_ENABLED) {
    setTimeout(() => {
        window.location.reload();
    }, 300);
} else {
    console.log("🟡 Page reload disabled - changes applied without refresh");
}
    };


   
    
    window.disableAllTracking = function() {
        console.log("❌ Disabling ALL tracking");
        localStorage.removeItem(CONSENT_KEY);
        localStorage.removeItem(CATEGORIES_KEY);
        
// Only reload if reload feature is enabled
if (window.COOKIE_SETTINGS && window.COOKIE_SETTINGS.RELOAD_ENABLED) {
    setTimeout(() => {
        window.location.reload();
    }, 300);
} else {
    console.log("🟡 Page reload disabled - changes applied without refresh");
}
    };
    
})();

