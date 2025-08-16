<?php
// Security settings - must be before session_start()
ini_set('session.cookie_httponly', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_secure', 1);

session_start();

// Prevent session fixation
if (!isset($_SESSION['initialized'])) {
    session_regenerate_id(true);
    $_SESSION['initialized'] = true;
}

// Admin credentials - store hashed password
$admin_username = "admin";
$hashed_password = password_hash("admin123", PASSWORD_BCRYPT); // Only do this once and store the hash

// Brute force protection
function checkBruteForce($ip) {
    $attempts_file = 'login_attempts.json';
    $max_attempts = 5;
    $lockout_time = 1800; // 30 minutes

    if (file_exists($attempts_file)) {
        $attempts = json_decode(file_get_contents($attempts_file), true);
    } else {
        $attempts = [];
    }

    // Clean old attempts
    foreach ($attempts as $attempt_ip => $data) {
        if ($data['time'] < time() - $lockout_time) {
            unset($attempts[$attempt_ip]);
        }
    }

    if (isset($attempts[$ip])) {
        if ($attempts[$ip]['count'] >= $max_attempts && 
            $attempts[$ip]['time'] > time() - $lockout_time) {
            return false; // IP is locked
        }
    }
    return true; // IP is allowed
}

function recordLoginAttempt($ip, $success = false) {
    $attempts_file = 'login_attempts.json';
    
    if (file_exists($attempts_file)) {
        $attempts = json_decode(file_get_contents($attempts_file), true);
    } else {
        $attempts = [];
    }

    if ($success) {
        unset($attempts[$ip]);
    } else {
        if (!isset($attempts[$ip])) {
            $attempts[$ip] = ['count' => 0, 'time' => time()];
        }
        $attempts[$ip]['count']++;
        $attempts[$ip]['time'] = time();
    }

    file_put_contents($attempts_file, json_encode($attempts));
}

// CSRF Protection
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('CSRF token validation failed');
    }
}

// Login handling
if (isset($_POST['login'])) {
    $ip = $_SERVER['REMOTE_ADDR'];
    
    if (!checkBruteForce($ip)) {
        $login_error = "Too many failed attempts. Please try again later.";
    } else {
        // Sanitize input
        $username = filter_var($_POST['username'], FILTER_SANITIZE_STRING);
        $password = $_POST['password'];

        if ($username === $admin_username && password_verify($password, $hashed_password)) {
            $_SESSION['admin'] = true;
            $_SESSION['login_time'] = time();
            $_SESSION['ip'] = $ip;
            recordLoginAttempt($ip, true);
            
            header("Location: index.php");
            exit;
        } else {
            recordLoginAttempt($ip);
            $login_error = "Invalid credentials!";
        }
    }
}

// Session timeout after 30 minutes
if (isset($_SESSION['admin'])) {
    if (time() - $_SESSION['login_time'] > 1800) {
        session_destroy();
        header("Location: index.php?timeout=1");
        exit;
    }
    
    // Prevent session hijacking
    if ($_SESSION['ip'] !== $_SERVER['REMOTE_ADDR']) {
        session_destroy();
        header("Location: index.php?error=security");
        exit;
    }
}

// Add logout handling here
if (isset($_GET['logout'])) {
    session_destroy();
    session_start();
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    header("Location: index.php");
    exit;
}

$uploadDir = 'uploads/';

// Create uploads directory if it doesn't exist and check permissions
if (!file_exists($uploadDir)) {
    mkdir($uploadDir, 0755, true);
    chmod($uploadDir, 0755);
}

// Check if directory is writable
if (!is_writable($uploadDir)) {
    error_log("Upload directory is not writable: " . $uploadDir);
}

// Only process upload/delete if logged in
if (isset($_SESSION['admin'])) {
    // Handle file upload
    if (isset($_POST['upload'])) {
        $file = $_FILES['file'];
        $fileName = basename($file['name']); // Sanitize filename
        $fileTmp = $file['tmp_name'];
        $targetPath = $uploadDir . $fileName;
        
        // Check if uploads directory is writable
        if (!is_writable($uploadDir)) {
            $message = "Error: Upload directory is not writable. Please check permissions.";
        } 
        // Check if file already exists
        elseif (file_exists($targetPath)) {
            $message = "Error: File already exists.";
        }
        // Try to move the uploaded file
        elseif (move_uploaded_file($fileTmp, $targetPath)) {
            // Set proper permissions for the uploaded file
            chmod($targetPath, 0644);
            $message = "File uploaded successfully!";
        } else {
            $message = "Error uploading file! Error code: " . $file['error'];
        }
    }

    // Handle file deletion
    if (isset($_POST['delete'])) {
        $fileToDelete = $uploadDir . $_POST['delete'];
        if (unlink($fileToDelete)) {
            $message = "File deleted successfully!";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="format-detection" content="telephone=no">
    <title>File Management System</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Poppins', sans-serif;
            background: #f0f2f5;
            color: #1a1a1a;
            line-height: 1.6;
        }

        .container {
            max-width: 1000px;
            margin: 40px auto;
            padding: 0 20px;
        }

        .card {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 30px;
            margin-bottom: 20px;
        }

        .login-form {
            max-width: 400px;
            margin: 80px auto;
        }

        h2 {
            color: #2c3e50;
            margin-bottom: 25px;
            font-weight: 600;
        }

        h3 {
            color: #34495e;
            margin-bottom: 20px;
            font-weight: 500;
        }

        .upload-form {
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }

        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            margin: 8px 0;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
        }

        input[type="submit"],
        .btn {
            background: #3498db;
            color: white;
            padding: 12px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.3s;
        }

        input[type="submit"]:hover,
        .btn:hover {
            background: #2980b9;
        }

        .logout {
            float: right;
            text-decoration: none;
            color: #e74c3c;
            font-weight: 500;
        }

        .message {
            padding: 15px;
            margin: 20px 0;
            border-radius: 6px;
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .error {
            color: #dc3545;
            margin: 10px 0;
            font-size: 14px;
        }

        .file-list {
            background: white;
            border-radius: 10px;
            padding: 30px;
        }

        .file-item {
            border: 1px solid #eee;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            background: white;
            transition: transform 0.2s ease;
        }

        .file-item:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }

        .file-name {
            font-weight: 500;
            color: #2c3e50;
        }

        .file-actions {
            display: flex;
            gap: 10px;
        }

        .file-actions a {
            text-decoration: none;
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 14px;
        }

        .download-btn {
            background: #2ecc71;
            color: white;
        }

        .delete-btn {
            background: #e74c3c;
            color: white;
        }

        .preview-container {
            margin: 15px 0;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            width: 100%;
        }

        .preview-wrapper {
            position: relative;
            width: 100%;
            display: flex;
            justify-content: center;
            align-items: center;
            margin-top: 10px;
            background: #fff;
            padding: 15px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }

        .preview {
            max-width: 100%;
            max-height: 400px;
            width: auto;
            height: auto;
            margin: 0;
            object-fit: contain;
            transition: transform 0.3s ease;
        }

        /* Update mobile styles */
        @media screen and (max-width: 768px) {
            .preview-container {
                padding: 10px;
                margin: 10px 0;
            }

            .preview-wrapper {
                padding: 10px;
                margin-top: 5px;
            }

            .preview {
                max-height: 300px;
                width: 100%;
                height: auto;
            }

            .preview-controls {
                position: static;
                transform: none;
                background: rgba(0, 0, 0, 0.8);
                padding: 10px;
                border-radius: 8px;
                margin-top: 10px;
                opacity: 1;
                width: 100%;
                display: flex;
                flex-direction: column;
                gap: 8px;
            }

            .preview-btn {
                width: 100%;
                padding: 12px;
                justify-content: center;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 6px;
            }

            /* PDF Preview mobile optimization */
            .pdf-preview {
                height: 70vh;
                min-height: 300px;
                width: 100%;
                border: none;
                border-radius: 8px;
            }

            /* Text Preview mobile optimization */
            .text-preview-wrapper {
                padding: 10px;
            }

            .text-preview {
                max-height: 300px;
                font-size: 14px;
                padding: 10px;
            }

            /* Video Preview mobile optimization */
            video.preview {
                width: 100%;
                height: auto;
                max-height: 300px;
            }
        }

        /* Small screen optimizations */
        @media screen and (max-width: 480px) {
            .preview-container {
                padding: 8px;
                margin: 8px 0;
            }

            .preview-wrapper {
                padding: 8px;
            }

            .preview {
                max-height: 250px;
            }

            .preview-controls {
                padding: 8px;
            }

            .preview-btn {
                padding: 10px;
                font-size: 14px;
            }

            .pdf-preview {
                height: 60vh;
                min-height: 250px;
            }

            .text-preview {
                max-height: 250px;
                font-size: 13px;
            }
        }

        /* Responsive Design */
        @media screen and (max-width: 768px) {
            .container {
                margin: 20px auto;
                padding: 0 15px;
            }

            .card {
                padding: 20px;
            }

            .login-form {
                margin: 40px auto;
                width: 90%;
            }

            h2 {
                font-size: 24px;
            }

            h3 {
                font-size: 20px;
            }

            .file-item {
                padding: 15px;
            }

            .file-info {
                flex-direction: column;
                gap: 10px;
            }

            .file-actions {
                flex-direction: column;
                width: 100%;
                margin-top: 10px;
            }

            .file-actions a,
            .file-actions button {
                width: 100%;
                text-align: center;
                margin: 5px 0;
            }

            .preview-container {
                padding: 10px;
            }

            .preview-wrapper {
                padding: 10px;
            }

            .preview {
                max-height: 300px;
            }

            .pdf-preview {
                height: 400px;
            }

            .text-preview {
                max-height: 300px;
            }

            .preview-controls {
                position: relative;
                bottom: 0;
                left: 0;
                transform: none;
                opacity: 1;
                margin-top: 10px;
                width: 100%;
                justify-content: center;
            }

            .upload-zone {
                padding: 15px;
            }

            input[type="file"] {
                width: 100%;
            }

            .message {
                padding: 12px;
                font-size: 14px;
            }

            /* Improve touch targets for mobile */
            .btn,
            input[type="submit"],
            button {
                padding: 12px 16px;
                min-height: 44px; /* minimum touch target size */
            }

            /* Better file type icon display */
            .file-type-icon {
                font-size: 20px;
            }

            /* Adjust logout button */
            .logout {
                float: none;
                display: block;
                text-align: right;
                margin-bottom: 20px;
            }

            /* Improve form inputs for mobile */
            input[type="text"],
            input[type="password"] {
                font-size: 16px; /* prevent iOS zoom on focus */
                padding: 10px;
            }

            /* Better spacing for file items */
            .file-name {
                word-break: break-all;
                margin-bottom: 10px;
            }
        }

        /* Even smaller screens */
        @media screen and (max-width: 480px) {
            .container {
                margin: 10px auto;
            }

            .card {
                padding: 15px;
            }

            h2 {
                font-size: 20px;
            }

            h3 {
                font-size: 18px;
            }

            .preview-controls {
                flex-direction: column;
                gap: 5px;
            }

            .preview-btn {
                width: 100%;
                justify-content: center;
            }

            /* Adjust padding for smaller screens */
            .upload-form,
            .file-list {
                padding: 15px;
            }

            /* Make file actions more touch-friendly */
            .file-actions a,
            .file-actions button {
                padding: 12px;
                font-size: 16px;
            }
        }

        /* Dark mode support for OLED screens */
        @media (prefers-color-scheme: dark) {
            body {
                background: #1a1a1a;
                color: #fff;
            }

            .card,
            .upload-form,
            .file-list,
            .preview-wrapper,
            .text-preview-wrapper {
                background: #2d2d2d;
                border-color: #3d3d3d;
            }

            .text-preview {
                background: #363636;
                color: #fff;
            }

            input[type="text"],
            input[type="password"] {
                background: #363636;
                color: #fff;
                border-color: #3d3d3d;
            }

            .message {
                background: #2d3748;
                color: #fff;
                border-color: #4a5568;
            }

            h2, h3 {
                color: #fff;
            }

            .file-item {
                background: #2d2d2d;
                border-color: #3d3d3d;
            }

            .file-name {
                color: #fff;
            }
        }

        /* Add these new styles */
        .upload-progress {
            display: none;
            margin-top: 15px;
            padding: 10px;
            border-radius: 8px;
            background: #f8f9fa;
        }

        .progress-bar {
            height: 20px;
            background: #eee;
            border-radius: 10px;
            overflow: hidden;
            margin-bottom: 10px;
        }

        .progress-fill {
            width: 0%;
            height: 100%;
            background: #3498db;
            transition: width 0.3s ease;
        }

        .progress-text {
            text-align: center;
            font-size: 14px;
            color: #666;
        }

        @media (prefers-color-scheme: dark) {
            .upload-progress {
                background: #2d2d2d;
            }
            .progress-bar {
                background: #404040;
            }
            .progress-text {
                color: #fff;
            }
        }
    </style>

    <script>
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        document.addEventListener('DOMContentLoaded', function() {
            const uploadForm = document.querySelector('form[enctype="multipart/form-data"]');
            const fileInput = uploadForm.querySelector('input[type="file"]');
            
            // Add progress elements
            const progressDiv = document.createElement('div');
            progressDiv.className = 'upload-progress';
            progressDiv.innerHTML = `
                <div class="progress-bar">
                    <div class="progress-fill"></div>
                </div>
                <div class="progress-text">Preparing upload...</div>
            `;
            uploadForm.insertBefore(progressDiv, uploadForm.querySelector('input[type="submit"]'));

            const progressBar = progressDiv.querySelector('.progress-fill');
            const progressText = progressDiv.querySelector('.progress-text');

            uploadForm.addEventListener('submit', function(e) {
                e.preventDefault();

                const file = fileInput.files[0];
                if (!file) return;

                const formData = new FormData();
                formData.append('file', file);
                formData.append('csrf_token', this.querySelector('[name="csrf_token"]').value);
                formData.append('upload', '1');

                const xhr = new XMLHttpRequest();
                progressDiv.style.display = 'block';

                xhr.upload.addEventListener('progress', function(e) {
                    if (e.lengthComputable) {
                        const percent = (e.loaded / e.total) * 100;
                        progressBar.style.width = percent + '%';
                        progressText.textContent = `Uploading: ${formatFileSize(e.loaded)} of ${formatFileSize(e.total)} (${percent.toFixed(1)}%)`;
                    }
                });

                xhr.addEventListener('load', function() {
                    if (xhr.status === 200) {
                        progressText.textContent = 'Upload complete!';
                        setTimeout(() => {
                            window.location.reload();
                        }, 500);
                    } else {
                        progressText.textContent = 'Upload failed!';
                    }
                });

                xhr.addEventListener('error', function() {
                    progressText.textContent = 'Upload failed!';
                });

                xhr.open('POST', 'index.php', true);
                xhr.send(formData);
            });

            // Reset progress on new file selection
            fileInput.addEventListener('change', function() {
                progressBar.style.width = '0%';
                progressText.textContent = 'Preparing upload...';
                progressDiv.style.display = 'none';
            });
        });
    </script>
</head>
<body>
    <div class="container">
        <?php if (!isset($_SESSION['admin'])): ?>
            <div class="login-form card">
                <h2><i class="fas fa-lock"></i> Admin Login</h2>
                <?php if (isset($login_error)): ?>
                    <p class="error"><i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($login_error); ?></p>
                <?php endif; ?>
                <?php if (isset($_GET['timeout'])): ?>
                    <p class="error"><i class="fas fa-clock"></i> Session expired. Please login again.</p>
                <?php endif; ?>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <p>
                        <label><i class="fas fa-user"></i> Username:</label>
                        <input type="text" name="username" required placeholder="Enter username"
                               pattern="[a-zA-Z0-9]+" title="Only alphanumeric characters allowed"
                               autocomplete="off">
                    </p>
                    <p>
                        <label><i class="fas fa-key"></i> Password:</label>
                        <input type="password" name="password" required placeholder="Enter password"
                               autocomplete="off">
                    </p>
                    <input type="submit" name="login" value="Login" class="btn">
                </form>
            </div>
        <?php else: ?>
            <a href="?logout" class="logout"><i class="fas fa-sign-out-alt"></i> Logout</a>
            <h2><i class="fas fa-folder-open"></i> File Management System</h2>
            
            <?php if (isset($message)): ?>
                <div class="message"><i class="fas fa-check-circle"></i> <?php echo $message; ?></div>
            <?php endif; ?>

            <div class="upload-form card">
                <h3><i class="fas fa-cloud-upload-alt"></i> Upload File</h3>
                <form method="POST" enctype="multipart/form-data">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <div class="upload-zone">
                        <input type="file" name="file" required>
                        <p>Drag & drop files or click to select</p>
                    </div>
                    <input type="submit" name="upload" value="Upload File" class="btn">
                </form>
            </div>

            <div class="file-list card">
                <h3><i class="fas fa-file-alt"></i> Available Files</h3>
                <?php
                $files = scandir($uploadDir);
                foreach ($files as $file) {
                    if ($file != '.' && $file != '..') {
                        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
                        $fileIcon = 'fa-file';
                        
                        // Set appropriate icon based on file type
                        if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif'])) {
                            $fileIcon = 'fa-file-image';
                        } elseif ($extension === 'mp4') {
                            $fileIcon = 'fa-file-video';
                        } elseif ($extension === 'pdf') {
                            $fileIcon = 'fa-file-pdf';
                        } elseif ($extension === 'txt') {
                            $fileIcon = 'fa-file-alt';
                        }

                        echo "<div class='file-item'>";
                        echo "<div class='file-info'>";
                        echo "<p class='file-name'><i class='fas {$fileIcon} file-type-icon'></i> {$file}</p>";
                        echo "<div class='file-actions'>";
                        echo "<a href='{$uploadDir}{$file}' download class='download-btn'><i class='fas fa-download'></i> Download</a>";
                        echo "<form method='POST' style='display:inline;'>";
                        echo "<input type='hidden' name='csrf_token' value='" . $_SESSION['csrf_token'] . "'>";
                        echo "<input type='hidden' name='delete' value='{$file}'>";
                        echo "<button type='submit' class='delete-btn' onclick='return confirm(\"Are you sure?\")'>";
                        echo "<i class='fas fa-trash'></i> Delete";
                        echo "</button>";
                        echo "</form>";
                        echo "</div></div>";

                        // Preview section
                        if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif'])) {
                            // Image preview
                            echo "<div class='preview-container'>";
                            echo "<div class='preview-wrapper'>";
                            echo "<img src='{$uploadDir}{$file}' class='preview' alt='{$file}' loading='lazy'>";
                            echo "</div>";
                            echo "<div class='preview-controls'>";
                            echo "<a href='{$uploadDir}{$file}' target='_blank' class='preview-btn'><i class='fas fa-expand'></i> Full View</a>";
                            echo "<a href='{$uploadDir}{$file}' download class='preview-btn'><i class='fas fa-download'></i> Download</a>";
                            echo "</div>";
                            echo "</div>";
                        }
                        elseif ($extension === 'mp4') {
                            // Video preview
                            echo "<div class='preview-container'>";
                            echo "<div class='preview-wrapper'>";
                            echo "<video controls playsinline class='preview'>";
                            echo "<source src='{$uploadDir}{$file}' type='video/mp4'>";
                            echo "Your browser does not support the video tag.";
                            echo "</video>";
                            echo "</div>";
                            echo "<div class='preview-controls'>";
                            echo "<a href='{$uploadDir}{$file}' target='_blank' class='preview-btn'><i class='fas fa-expand'></i> Full View</a>";
                            echo "<a href='{$uploadDir}{$file}' download class='preview-btn'><i class='fas fa-download'></i> Download</a>";
                            echo "</div>";
                            echo "</div>";
                        }
                        elseif ($extension === 'pdf') {
                            // PDF preview
                            echo "<div class='preview-container'>";
                            echo "<div class='preview-wrapper'>";
                            $pdfUrl = urlencode("https://yourdoamin.com/uploads/" . $file);
                            echo "<iframe src='https://docs.google.com/viewerng/viewer?url={$pdfUrl}&embedded=true' 
                                  class='preview pdf-preview' frameborder='0' scrolling='auto'></iframe>";
                            echo "</div>";
                            echo "<div class='preview-controls'>";
                            echo "<a href='{$uploadDir}{$file}' target='_blank' class='preview-btn'><i class='fas fa-expand'></i> Full View</a>";
                            echo "<a href='{$uploadDir}{$file}' download class='preview-btn'><i class='fas fa-download'></i> Download</a>";
                            echo "</div>";
                            echo "</div>";
                        }
                        elseif ($extension === 'txt') {
                            // Text file preview
                            echo "<div class='preview-container'>";
                            echo "<div class='preview-wrapper text-preview-wrapper'>";
                            echo "<div class='text-preview'>";
                            $content = htmlspecialchars(file_get_contents($uploadDir . $file));
                            echo "<pre>" . $content . "</pre>";
                            echo "</div>";
                            echo "</div>";
                            echo "<div class='preview-controls'>";
                            echo "<a href='{$uploadDir}{$file}' target='_blank' class='preview-btn'><i class='fas fa-expand'></i> Full View</a>";
                            echo "<a href='{$uploadDir}{$file}' download class='preview-btn'><i class='fas fa-download'></i> Download</a>";
                            echo "</div>";
                            echo "</div>";
                        }
                        echo "</div>";
                    }
                }
                ?>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>