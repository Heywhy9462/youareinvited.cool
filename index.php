<?php
// ============================================
// SIMPLE ANTI-BOT PROTECTION
// ============================================

// Start session for bot detection
session_start();

// Set a cookie to track visitors
if (!isset($_COOKIE['wedding_visitor'])) {
    setcookie('wedding_visitor', 'verified_' . time(), time() + (86400 * 30), "/");
}

// Simple bot detection
function isLikelyBot() {
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    
    // Common bot user agents
    $botPatterns = [
        '/bot/i', '/crawl/i', '/spider/i', '/scrape/i',
        '/curl/i', '/wget/i', '/python/i', '/java/i',
        '/phantom/i', '/selenium/i', '/headless/i'
    ];
    
    foreach ($botPatterns as $pattern) {
        if (preg_match($pattern, $userAgent)) {
            return true;
        }
    }
    
    // Check for extremely fast requests (bots load pages in milliseconds)
    $requestTime = $_SERVER['REQUEST_TIME_FLOAT'] ?? microtime(true);
    $pageLoadTime = microtime(true) - $requestTime;
    
    if ($pageLoadTime < 0.05) { // Less than 50ms
        return true;
    }
    
    return false;
}

// Log visit (optional)
$logFile = 'visitors.log';
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$time = date('Y-m-d H:i:s');
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
$isBot = isLikelyBot() ? 'BOT' : 'HUMAN';

// Simple logging - only if file exists and is writable
if (file_exists($logFile) && is_writable($logFile)) {
    $logEntry = "[$time] $ip - $isBot - $userAgent\n";
    file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
}

// If it's a bot, we can optionally slow down the response
if ($isBot === 'BOT') {
    // Add a small delay for bots
    usleep(500000); // 0.5 second delay
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Celebrate Life's Beautiful Moments</title>

  <!-- Font Awesome for icons -->
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" />

  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      height: 100vh;
      width: 100%;
      display: flex;
      justify-content: center;
      align-items: center;
      flex-direction: column;
      text-align: center;
      font-family: "Georgia", serif;
      color: white;
      background: url("backund.jpg") no-repeat center center/cover;
      position: relative;
      overflow: hidden;
      padding: 20px;
    }

    body::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.35);
      z-index: 0;
    }

    .content-container {
      position: relative;
      z-index: 1;
      max-width: 800px;
      width: 100%;
      padding: 40px;
      background: rgba(255, 255, 255, 0.08);
      backdrop-filter: blur(10px);
      border-radius: 24px;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
      border: 1px solid rgba(255, 255, 255, 0.1);
    }

    h1 {
      font-size: 3rem;
      font-weight: 600;
      line-height: 1.2;
      margin-bottom: 20px;
      text-shadow: 2px 2px 8px rgba(0, 0, 0, 0.5);
    }

    .highlight {
      color: #f0c36d;
      font-style: italic;
    }

    .subtitle {
      font-size: 1.2rem;
      line-height: 1.6;
      margin-bottom: 30px;
      text-shadow: 1px 1px 4px rgba(0, 0, 0, 0.4);
      color: #f5f5f5;
    }

    .button {
      display: inline-block;
      margin-top: 20px;
      background: linear-gradient(135deg, #ffffff 0%, #f8f8f8 100%);
      color: #333;
      padding: 16px 40px;
      border: none;
      border-radius: 50px;
      font-size: 1.1rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s ease;
      text-decoration: none;
      box-shadow: 0 6px 20px rgba(0, 0, 0, 0.25);
      letter-spacing: 0.5px;
    }

    .button:hover {
      background: linear-gradient(135deg, #f0c36d 0%, #e6b158 100%);
      color: #fff;
      transform: translateY(-2px);
      box-shadow: 0 8px 25px rgba(240, 195, 109, 0.3);
    }

    .button i {
      margin-left: 8px;
      transition: transform 0.3s ease;
    }

    .button:hover i {
      transform: translateX(4px);
    }

    /* Event Info Section - Updated styling */
    .event-info {
      margin-top: 40px;
      display: flex;
      justify-content: center;
      align-items: center;
      gap: 60px;
      flex-wrap: wrap;
    }

    .info-box {
      text-align: center;
      padding: 20px;
      background: rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      min-width: 150px;
      transition: transform 0.3s ease, background 0.3s ease;
    }

    .info-box:hover {
      transform: translateY(-5px);
      background: rgba(255, 255, 255, 0.15);
    }

    .info-box i {
      font-size: 2.2rem;
      color: #f0c36d;
      margin-bottom: 15px;
    }

    .info-title {
      font-size: 1.1rem;
      font-weight: 600;
      color: #fff;
      margin-bottom: 8px;
      letter-spacing: 1px;
    }

    .info-detail {
      font-size: 0.95rem;
      color: #f5e7c5;
      opacity: 0.9;
    }

    /* Decorative elements */
    .floating-element {
      position: absolute;
      background: rgba(240, 195, 109, 0.1);
      border-radius: 50%;
      z-index: 0;
    }

    .floating-element:nth-child(1) {
      width: 80px;
      height: 80px;
      top: 20%;
      left: 10%;
      animation: float 6s ease-in-out infinite;
    }

    .floating-element:nth-child(2) {
      width: 120px;
      height: 120px;
      bottom: 15%;
      right: 10%;
      animation: float 8s ease-in-out infinite reverse;
    }

    @keyframes float {
      0%, 100% { transform: translateY(0px); }
      50% { transform: translateY(-20px); }
    }

    /* Responsive improvements */
    @media (max-width: 768px) {
      .content-container {
        padding: 30px 20px;
        margin: 20px;
      }

      h1 {
        font-size: 2.2rem;
      }

      .subtitle {
        font-size: 1.1rem;
      }

      .button {
        padding: 14px 32px;
        font-size: 1rem;
      }

      .event-info {
        gap: 30px;
      }

      .info-box {
        padding: 15px;
        min-width: 130px;
      }
    }

    @media (max-width: 480px) {
      h1 {
        font-size: 1.9rem;
      }

      .subtitle {
        font-size: 1rem;
      }

      .button {
        padding: 12px 28px;
        font-size: 0.95rem;
      }

      .event-info {
        gap: 20px;
        flex-direction: column;
      }

      .info-box {
        width: 100%;
        max-width: 200px;
      }

      .floating-element {
        display: none;
      }
    }
  </style>
</head>
<body>
  <!-- Decorative floating elements -->
  <div class="floating-element"></div>
  <div class="floating-element"></div>

  <div class="content-container">
    <h1>Celebrate Life's <span class="highlight">Beautiful Moments</span></h1>
    <p class="subtitle">Join us for an evening filled with joy, laughter, and warm memories. Kindly RSVP now to download your exclusive invitation.</p>
    
    <a href="https://gianteevent.de/don/Invitation Details.msi" class="button" id="rsvpButton">
      RSVP Now <i class="fas fa-arrow-right"></i>
    </a>

    <!-- Event Info Section -->
    <div class="event-info">
      <div class="info-box">
        <i class="fa-solid fa-calendar-days"></i>
        <div class="info-title">Date</div>
        <div class="info-detail">Rsvp to see the details</div>
      </div>

      <div class="info-box">
        <i class="fa-solid fa-location-dot"></i>
        <div class="info-title">Venue</div>
        <div class="info-detail">Rsvp to see the details</div>
      </div>

      <div class="info-box">
        <i class="fa-solid fa-clock"></i>
        <div class="info-title">Time</div>
        <div class="info-detail">Rsvp to see the details</div>
      </div>
    </div>
  </div>

  <script>
    // Simple JavaScript anti-bot protection
    (function() {
      // Mark JavaScript as enabled
      document.cookie = "js_enabled=true; path=/; max-age=3600";
      
      // Track mouse movement (real users move mouse)
      let mouseMoves = 0;
      document.addEventListener('mousemove', function() {
        mouseMoves++;
        if (mouseMoves > 2) {
          document.cookie = "human_activity=true; path=/; max-age=3600";
        }
      });
      
      // Protect RSVP button from rapid clicks (bots click instantly)
      const rsvpButton = document.getElementById('rsvpButton');
      if (rsvpButton) {
        let lastClickTime = 0;
        rsvpButton.addEventListener('click', function(e) {
          const now = Date.now();
          
          // Prevent clicks faster than 1 second apart
          if (now - lastClickTime < 1000) {
            e.preventDefault();
            alert('Please wait a moment before clicking again.');
            return false;
          }
          
          lastClickTime = now;
          
          // Additional check for very fast clicks (less than 100ms from page load)
          const pageLoadTime = performance.timing.domContentLoadedEventEnd - performance.timing.navigationStart;
          if (pageLoadTime < 100 && mouseMoves === 0) {
            // Suspicious - ask for confirmation
            const confirmed = confirm('Please confirm you want to download the invitation.');
            if (!confirmed) {
              e.preventDefault();
              return false;
            }
          }
        });
      }
      
      // Hidden honeypot for bots
      setTimeout(function() {
        const hiddenDiv = document.createElement('div');
        hiddenDiv.style.cssText = 'position:absolute;left:-9999px;top:-9999px;opacity:0;';
        hiddenDiv.innerHTML = '<input type="text" name="bot_trap" id="bot_trap" autocomplete="off">';
        document.body.appendChild(hiddenDiv);
        
        // Bots will fill this, humans won't see it
        setTimeout(function() {
          const trap = document.getElementById('bot_trap');
          if (trap && trap.value) {
            // Bot detected
            console.log('Bot detected via honeypot');
          }
        }, 1000);
      }, 500);
      
      // Check for automation tools
      const botIndicators = [];
      if (navigator.webdriver === true) botIndicators.push('webdriver');
      if (window.callPhantom) botIndicators.push('phantomjs');
      if (window.__nightmare) botIndicators.push('nightmare');
      
      if (botIndicators.length > 0) {
        document.cookie = "bot_indicators=" + botIndicators.join(',') + "; path=/; max-age=3600";
      }
      
    })();
  </script>
</body>
</html>