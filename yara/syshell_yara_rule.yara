rule syshell_webshell_framework
{
    meta:
        description = "Detects syshell web shell framework"
        author = "syro"
        date = "2025-08-10"
        version = "1.0"
        reference = "https://github.com/0xsyr0/syshell"
        severity = "high"
        category = "webshell"
        
    strings:
        // Function signature patterns
        $func1 = "diagKeyDecode" ascii
        $func2 = "diagLogParser" ascii
        $func3 = "dataStreamFilter" ascii
        
        // Unique interface elements
        $ui1 = "System Management Interface" ascii
        $ui2 = "System Diagnostics" ascii
        $ui3 = "Restricted operations console" ascii
        
        // Encryption patterns
        $crypt1 = "openssl_decrypt(base64_decode(" ascii
        $crypt2 = "'AES-256-CBC'" ascii
        
        // CSS styling patterns (unique to syshell)
        $style1 = "--ink:#e6e6f0; --muted:#b7b0c9; --bg1:#1a1025" ascii
        $style2 = "conic-gradient(from 210deg, var(--accent)" ascii
        
        // JavaScript patterns
        $js1 = "getElementById('current-time')" ascii
        $js2 = "updateTime();" ascii
        
        // Session management
        $session1 = "$_SESSION['auth']" ascii
        $session2 = "$_SESSION['pwd']" ascii
        $session3 = "$_SESSION['cwd']" ascii
        
    condition:
        // Must be a PHP file
        uint16(0) == 0x3c3f and // "<?php" or "<?="
        
        // Core detection logic
        (
            // Function signatures (high confidence)
            all of ($func*) or
            
            // UI elements + encryption (medium confidence)
            (any of ($ui*) and any of ($crypt*)) or
            
            // Styling + session management (medium confidence)
            (any of ($style*) and 2 of ($session*)) or
            
            // Multiple component match (high confidence)
            (any of ($ui*) and any of ($js*) and any of ($session*))
        ) and
        
        // File size constraints (typical web shell range)
        filesize < 100KB and filesize > 5KB
}
