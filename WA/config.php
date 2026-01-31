<?php
// Anti-bot protection system
// No CAPTCHA, no "I'm not a robot" - completely transparent

function checkIfBot() {
    // Start with assumption it's human
    $isBot = false;
    
    // 1. Check session - if already verified, trust it
    if (isset($_SESSION['verified_human']) && $_SESSION['verified_human'] === true) {
        // Check if verification is still fresh (within 1 hour)
        if (isset($_SESSION['verification_time']) && 
            (time() - $_SESSION['verification_time']) < 3600) {
            return false; // Already verified human
        }
    }
    
    // 2. Check for common bot user agents
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $botPatterns = [
        '/bot/i', '/crawl/i', '/spider/i', '/scrape/i',
        '/curl/i', '/wget/i', '/python/i', '/java/i',
        '/phantom/i', '/selenium/i', '/headless/i',
        '/archive/i', '/indexer/i', '/scan/i'
    ];
    
    foreach ($botPatterns as $pattern) {
        if (preg_match($pattern, $userAgent)) {
            $isBot = true;
            break;
        }
    }
    
    // 3. Check for missing JavaScript support (basic bots)
    if (isset($_COOKIE['js_disabled']) && $_COOKIE['js_disabled'] === 'true') {
        $isBot = true;
    }
    
    // 4. Check for suspicious request patterns
    $requestTime = $_SERVER['REQUEST_TIME_FLOAT'] ?? time();
    $serverLoadTime = microtime(true) - $requestTime;
    
    // Bots often make requests too quickly
    if ($serverLoadTime < 0.1) { // Less than 100ms
        $isBot = true;
    }
    
    // 5. Check referrer (if available)
    $referrer = $_SERVER['HTTP_REFERER'] ?? '';
    if ($referrer && !filter_var($referrer, FILTER_VALIDATE_URL)) {
        $isBot = true;
    }
    
    // 6. Check honeypot field from form (if any)
    if (isset($_POST['honeypot']) && !empty($_POST['honeypot'])) {
        $isBot = true;
    }
    
    // 7. Check for common bot headers
    $headers = getallheaders();
    $botHeaders = [
        'X-Scanner', 'X-Crawler', 'X-Bot', 'X-Forwarded-For-Bot'
    ];
    
    foreach ($botHeaders as $header) {
        if (isset($headers[$header])) {
            $isBot = true;
            break;
        }
    }
    
    // 8. Rate limiting check (simple version)
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $requestKey = 'request_count_' . md5($ip);
    
    if (!isset($_SESSION[$requestKey])) {
        $_SESSION[$requestKey] = 1;
        $_SESSION['first_request_time'] = time();
    } else {
        $_SESSION[$requestKey]++;
        
        // If more than 10 requests in 10 seconds, likely a bot
        $timeElapsed = time() - $_SESSION['first_request_time'];
        if ($_SESSION[$requestKey] > 10 && $timeElapsed < 10) {
            $isBot = true;
        }
    }
    
    // 9. Check for human activity cookies (set by JavaScript)
    $humanActivity = isset($_COOKIE['human_activity']) || 
                    isset($_COOKIE['keyboard_activity']) || 
                    isset($_COOKIE['scroll_activity']) ||
                    isset($_COOKIE['page_focused']);
    
    if ($humanActivity) {
        $isBot = false; // Human activity detected
    }
    
    return $isBot;
}

// Set a cookie for JavaScript detection
if (!isset($_COOKIE['js_enabled'])) {
    setcookie('js_enabled', 'true', time() + (86400 * 30), "/");
}

// For JavaScript-disabled clients
if (!isset($_COOKIE['js_enabled'])) {
    setcookie('js_disabled', 'true', time() + (86400 * 30), "/");
}
?>