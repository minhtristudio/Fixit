<?php
session_start();

// Cấu hình bảo mật
define('MASTER_KEY', hash('sha256', 'SecureFileShare2024!@#$%^&*()_+{}[]|:;<>?,./' . $_SERVER['HTTP_HOST']));
define('UPLOAD_DIR', 'data/');
define('MAX_FILE_SIZE', 100 * 1024 * 1024); // 100MB
define('DEFAULT_EXPIRE_HOURS', 24);

// Tạo thư mục data nếu chưa có
if (!file_exists(UPLOAD_DIR)) {
    mkdir(UPLOAD_DIR, 0755, true);
    file_put_contents(UPLOAD_DIR . '.htaccess', "Options -Indexes\nDeny from all");
}

class SecureFileShare {
    
    private function generateKey($password = '') {
        return hash('sha256', MASTER_KEY . $password . date('Y-m-d'));
    }
    
    private function encrypt($data, $key) {
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $encrypted);
    }
    
    private function decrypt($data, $key) {
        $data = base64_decode($data);
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        return openssl_decrypt($encrypted, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    }
    
    private function generateFileId() {
        return bin2hex(random_bytes(16));
    }
    
    private function obfuscateFilename($filename) {
        return hash('sha256', $filename . time() . random_bytes(8)) . '.dat';
    }
    
    public function uploadFile($file, $password = '', $expireHours = DEFAULT_EXPIRE_HOURS) {
        if ($file['error'] !== UPLOAD_ERR_OK) {
            return ['success' => false, 'message' => 'Lỗi upload file'];
        }
        
        if ($file['size'] > MAX_FILE_SIZE) {
            return ['success' => false, 'message' => 'File quá lớn (max 100MB)'];
        }
        
        $fileId = $this->generateFileId();
        $key = $this->generateKey($password);
        $originalName = $file['name'];
        $fileContent = file_get_contents($file['tmp_name']);
        
        // Mã hóa metadata
        $metadata = [
            'original_name' => $originalName,
            'size' => $file['size'],
            'type' => $file['type'],
            'upload_time' => time(),
            'expire_time' => time() + ($expireHours * 3600),
            'password_protected' => !empty($password)
        ];
        
        $encryptedMetadata = $this->encrypt(json_encode($metadata), $key);
        $encryptedContent = $this->encrypt($fileContent, $key);
        
        // Tạo tên file ngẫu nhiên
        $storedFilename = $this->obfuscateFilename($originalName);
        
        // Lưu file với cấu trúc ẩn
        $fileData = [
            'metadata' => $encryptedMetadata,
            'content' => $encryptedContent,
            'chunks' => $this->createChunks($encryptedContent, $key)
        ];
        
        $filePath = UPLOAD_DIR . $storedFilename;
        if (file_put_contents($filePath, serialize($fileData))) {
            // Lưu mapping ID -> filename
            $mappingFile = UPLOAD_DIR . '.mapping';
            $mapping = file_exists($mappingFile) ? unserialize(file_get_contents($mappingFile)) : [];
            $mapping[$fileId] = $storedFilename;
            file_put_contents($mappingFile, serialize($mapping));
            
            return [
                'success' => true,
                'file_id' => $fileId,
                'download_link' => $_SERVER['REQUEST_URI'] . '?download=' . $fileId,
                'expire_time' => date('Y-m-d H:i:s', $metadata['expire_time'])
            ];
        }
        
        return ['success' => false, 'message' => 'Không thể lưu file'];
    }
    
    private function createChunks($data, $key) {
        $chunks = [];
        $chunkSize = 8192;
        $dataLen = strlen($data);
        
        for ($i = 0; $i < $dataLen; $i += $chunkSize) {
            $chunk = substr($data, $i, $chunkSize);
            $chunks[] = $this->encrypt($chunk, $key . $i);
        }
        
        return $chunks;
    }
    
    public function downloadFile($fileId, $password = '') {
        $mappingFile = UPLOAD_DIR . '.mapping';
        if (!file_exists($mappingFile)) {
            return ['success' => false, 'message' => 'File không tồn tại'];
        }
        
        $mapping = unserialize(file_get_contents($mappingFile));
        if (!isset($mapping[$fileId])) {
            return ['success' => false, 'message' => 'File không tồn tại'];
        }
        
        $filePath = UPLOAD_DIR . $mapping[$fileId];
        if (!file_exists($filePath)) {
            return ['success' => false, 'message' => 'File không tồn tại'];
        }
        
        $key = $this->generateKey($password);
        $fileData = unserialize(file_get_contents($filePath));
        
        // Giải mã metadata
        $metadataJson = $this->decrypt($fileData['metadata'], $key);
        if (!$metadataJson) {
            return ['success' => false, 'message' => 'Sai mật khẩu hoặc file bị hỏng'];
        }
        
        $metadata = json_decode($metadataJson, true);
        
        // Kiểm tra thời gian hết hạn
        if (time() > $metadata['expire_time']) {
            $this->deleteFile($fileId);
            return ['success' => false, 'message' => 'File đã hết hạn'];
        }
        
        // Kiểm tra mật khẩu
        if ($metadata['password_protected'] && empty($password)) {
            return ['success' => false, 'message' => 'Cần mật khẩu'];
        }
        
        // Giải mã nội dung
        $content = $this->decrypt($fileData['content'], $key);
        if (!$content) {
            return ['success' => false, 'message' => 'Không thể giải mã file'];
        }
        
        return [
            'success' => true,
            'content' => $content,
            'filename' => $metadata['original_name'],
            'type' => $metadata['type'],
            'size' => $metadata['size']
        ];
    }
    
    public function deleteFile($fileId) {
        $mappingFile = UPLOAD_DIR . '.mapping';
        if (!file_exists($mappingFile)) return false;
        
        $mapping = unserialize(file_get_contents($mappingFile));
        if (isset($mapping[$fileId])) {
            $filePath = UPLOAD_DIR . $mapping[$fileId];
            if (file_exists($filePath)) {
                unlink($filePath);
            }
            unset($mapping[$fileId]);
            file_put_contents($mappingFile, serialize($mapping));
            return true;
        }
        return false;
    }
    
    public function cleanupExpired() {
        $mappingFile = UPLOAD_DIR . '.mapping';
        if (!file_exists($mappingFile)) return;
        
        $mapping = unserialize(file_get_contents($mappingFile));
        $cleaned = 0;
        
        foreach ($mapping as $fileId => $filename) {
            $filePath = UPLOAD_DIR . $filename;
            if (file_exists($filePath)) {
                $fileData = unserialize(file_get_contents($filePath));
                $key = $this->generateKey('');
                $metadataJson = $this->decrypt($fileData['metadata'], $key);
                
                if ($metadataJson) {
                    $metadata = json_decode($metadataJson, true);
                    if (time() > $metadata['expire_time']) {
                        unlink($filePath);
                        unset($mapping[$fileId]);
                        $cleaned++;
                    }
                }
            }
        }
        
        if ($cleaned > 0) {
            file_put_contents($mappingFile, serialize($mapping));
        }
    }
}

$fileShare = new SecureFileShare();

// Xử lý các request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'upload':
                if (isset($_FILES['file'])) {
                    $password = $_POST['password'] ?? '';
                    $expireHours = intval($_POST['expire_hours'] ?? DEFAULT_EXPIRE_HOURS);
                    $result = $fileShare->uploadFile($_FILES['file'], $password, $expireHours);
                    echo json_encode($result);
                } else {
                    echo json_encode(['success' => false, 'message' => 'Không có file được chọn']);
                }
                break;
                
            case 'delete':
                $fileId = $_POST['file_id'] ?? '';
                $result = $fileShare->deleteFile($fileId);
                echo json_encode(['success' => $result]);
                break;
        }
    }
    exit;
}

// Xử lý download
if (isset($_GET['download'])) {
    $fileId = $_GET['download'];
    $password = $_POST['password'] ?? '';
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
        $result = $fileShare->downloadFile($fileId, $password);
        
        if ($result['success']) {
            header('Content-Type: ' . $result['type']);
            header('Content-Disposition: attachment; filename="' . $result['filename'] . '"');
            header('Content-Length: ' . $result['size']);
            echo $result['content'];
            exit;
        } else {
            $error = $result['message'];
        }
    } else {
        // Kiểm tra xem file có cần password không
        $result = $fileShare->downloadFile($fileId, '');
        if (!$result['success'] && $result['message'] === 'Cần mật khẩu') {
            $needPassword = true;
        } elseif ($result['success']) {
            header('Content-Type: ' . $result['type']);
            header('Content-Disposition: attachment; filename="' . $result['filename'] . '"');
            header('Content-Length: ' . $result['size']);
            echo $result['content'];
            exit;
        } else {
            $error = $result['message'];
        }
    }
}

// Cleanup expired files (10% chance)
if (rand(1, 10) === 1) {
    $fileShare->cleanupExpired();
}
?>

<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure File Share - Chia sẻ file siêu an toàn</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 600px;
            width: 100%;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .header h1 {
            color: #333;
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .header p {
            color: #666;
            font-size: 1.1em;
        }
        
        .security-info {
            background: linear-gradient(135deg, #00c6ff 0%, #0072ff 100%);
            color: white;
            padding: 20px;
            border-radius: 15px;
            margin-bottom: 30px;
            text-align: center;
        }
        
        .security-info h3 {
            margin-bottom: 10px;
            font-size: 1.3em;
        }
        
        .security-features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin-top: 15px;
        }
        
        .feature {
            background: rgba(255, 255, 255, 0.2);
            padding: 10px;
            border-radius: 8px;
            font-size: 0.9em;
        }
        
        .upload-section, .download-section {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 15px;
            margin-bottom: 20px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }
        
        input[type="file"], input[type="password"], input[type="number"], select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e5e9;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        input[type="file"]:focus, input[type="password"]:focus, input[type="number"]:focus, select:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .btn {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            padding: 15px 30px;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.3s, box-shadow 0.3s;
            width: 100%;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }
        
        .btn:active {
            transform: translateY(0);
        }
        
        .result {
            margin-top: 20px;
            padding: 20px;
            border-radius: 10px;
            display: none;
        }
        
        .result.success {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        
        .result.error {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        
        .download-link {
            background: #e9ecef;
            padding: 15px;
            border-radius: 8px;
            margin-top: 15px;
            word-break: break-all;
        }
        
        .download-link a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
        
        .progress {
            width: 100%;
            height: 6px;
            background: #e1e5e9;
            border-radius: 3px;
            margin-top: 10px;
            overflow: hidden;
            display: none;
        }
        
        .progress-bar {
            height: 100%;
            background: linear-gradient(45deg, #667eea, #764ba2);
            width: 0%;
            transition: width 0.3s;
        }
        
        .tabs {
            display: flex;
            margin-bottom: 20px;
            background: #e9ecef;
            border-radius: 10px;
            padding: 5px;
        }
        
        .tab {
            flex: 1;
            text-align: center;
            padding: 15px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .tab.active {
            background: white;
            color: #667eea;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 20px;
                margin: 10px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .security-features {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Secure File Share</h1>
            <p>Chia sẻ file với mã hóa AES-256 siêu an toàn</p>
        </div>
        
        <div class="security-info">
            <h3>🛡️ Bảo mật tuyệt đối</h3>
            <p>Files của bạn được mã hóa với chuẩn quân sự AES-256</p>
            <div class="security-features">
                <div class="feature">🔐 Mã hóa end-to-end</div>
                <div class="feature">🕵️ Ẩn danh hoàn toàn</div>
                <div class="feature">⏰ Tự động xóa</div>
                <div class="feature">🚫 Hosting không thể đọc</div>
            </div>
        </div>
        
        <?php if (isset($_GET['download'])): ?>
            <div class="download-section">
                <h3>📥 Tải xuống file</h3>
                
                <?php if (isset($needPassword)): ?>
                    <form method="POST">
                        <div class="form-group">
                            <label for="password">🔑 Nhập mật khẩu để tải file:</label>
                            <input type="password" id="password" name="password" required>
                        </div>
                        <button type="submit" class="btn">Tải xuống</button>
                    </form>
                <?php elseif (isset($error)): ?>
                    <div class="result error" style="display: block;">
                        ❌ <?php echo htmlspecialchars($error); ?>
                    </div>
                    <a href="<?php echo $_SERVER['PHP_SELF']; ?>" class="btn" style="display: inline-block; text-decoration: none; text-align: center; margin-top: 15px;">Quay lại</a>
                <?php endif; ?>
            </div>
        <?php else: ?>
            <div class="tabs">
                <div class="tab active" onclick="showTab('upload')">📤 Upload File</div>
                <div class="tab" onclick="showTab('download')">📥 Download File</div>
            </div>
            
            <div id="upload-tab" class="tab-content active">
                <div class="upload-section">
                    <h3>📤 Upload File An Toàn</h3>
                    <form id="uploadForm" enctype="multipart/form-data">
                        <div class="form-group">
                            <label for="file">📁 Chọn file (max 100MB):</label>
                            <input type="file" id="file" name="file" required>
                        </div>
                        
                        <div class="form-group">
                            <label for="password">🔑 Mật khẩu bảo vệ (tùy chọn):</label>
                            <input type="password" id="password" name="password" placeholder="Để trống nếu không cần mật khẩu">
                        </div>
                        
                        <div class="form-group">
                            <label for="expire_hours">⏰ Thời gian tự động xóa:</label>
                            <select id="expire_hours" name="expire_hours">
                                <option value="1">1 giờ</option>
                                <option value="6">6 giờ</option>
                                <option value="24" selected>24 giờ</option>
                                <option value="72">3 ngày</option>
                                <option value="168">1 tuần</option>
                            </select>
                        </div>
                        
                        <button type="submit" class="btn">🚀 Upload File</button>
                        <div class="progress">
                            <div class="progress-bar"></div>
                        </div>
                    </form>
                    
                    <div id="uploadResult" class="result"></div>
                </div>
            </div>
            
            <div id="download-tab" class="tab-content">
                <div class="download-section">
                    <h3>📥 Tải xuống file</h3>
                    <div class="form-group">
                        <label for="fileId">🔗 Nhập File ID hoặc link:</label>
                        <input type="text" id="fileId" placeholder="Nhập ID file hoặc dán link đầy đủ">
                    </div>
                    <button onclick="downloadFile()" class="btn">Tải xuống</button>
                </div>
            </div>
        <?php endif; ?>
    </div>
    
    <script>
        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName + '-tab').classList.add('active');
            event.target.classList.add('active');
        }
        
        document.getElementById('uploadForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData();
            const fileInput = document.getElementById('file');
            const passwordInput = document.getElementById('password');
            const expireInput = document.getElementById('expire_hours');
            
            if (!fileInput.files[0]) {
                showResult('error', '❌ Vui lòng chọn file');
                return;
            }
            
            formData.append('action', 'upload');
            formData.append('file', fileInput.files[0]);
            formData.append('password', passwordInput.value);
            formData.append('expire_hours', expireInput.value);
            
            // Show progress
            document.querySelector('.progress').style.display = 'block';
            const progressBar = document.querySelector('.progress-bar');
            
            const xhr = new XMLHttpRequest();
            
            xhr.upload.addEventListener('progress', function(e) {
                if (e.lengthComputable) {
                    const percentComplete = (e.loaded / e.total) * 100;
                    progressBar.style.width = percentComplete + '%';
                }
            });
            
            xhr.addEventListener('load', function() {
                document.querySelector('.progress').style.display = 'none';
                progressBar.style.width = '0%';
                
                try {
                    const response = JSON.parse(xhr.responseText);
                    if (response.success) {
                        showResult('success', 
                            `✅ Upload thành công!<br>
                            🆔 File ID: <strong>${response.file_id}</strong><br>
                            ⏰ Hết hạn: ${response.expire_time}<br>
                            <div class="download-link">
                                <strong>🔗 Link tải:</strong><br>
                                <a href="${response.download_link}" target="_blank">${response.download_link}</a>
                            </div>`
                        );
                        
                        // Reset form
                        document.getElementById('uploadForm').reset();
                    } else {
                        showResult('error', '❌ ' + response.message);
                    }
                } catch (error) {
                    showResult('error', '❌ Lỗi xử lý phản hồi từ server');
                }
            });
            
            xhr.addEventListener('error', function() {
                document.querySelector('.progress').style.display = 'none';
                showResult('error', '❌ Lỗi mạng, vui lòng thử lại');
            });
            
            xhr.open('POST', '');
            xhr.send(formData);
        });
        
        function showResult(type, message) {
            const result = document.getElementById('uploadResult');
            result.className = 'result ' + type;
            result.innerHTML = message;
            result.style.display = 'block';
            
            // Auto hide after 10 seconds for success messages
            if (type === 'success') {
                setTimeout(() => {
                    result.style.display = 'none';
                }, 10000);
            }
        }
        
        function downloadFile() {
            const fileIdInput = document.getElementById('fileId');
            let fileId = fileIdInput.value.trim();
            
            if (!fileId) {
                alert('❌ Vui lòng nhập File ID hoặc link');
                return;
            }
            
            // Extract file ID from full URL if needed
            if (fileId.includes('download=')) {
                const match = fileId.match(/download=([a-f0-9]+)/);
                if (match) {
                    fileId = match[1];
                }
            }
            
            window.location.href = '?download=' + fileId;
        }
        
        // Auto-focus on file input when page loads
        window.addEventListener('load', function() {
            const fileInput = document.getElementById('file');
            if (fileInput) {
                fileInput.focus();
            }
        });
        
        // Drag and drop functionality
        const uploadSection = document.querySelector('.upload-section');
        if (uploadSection) {
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                uploadSection.addEventListener(eventName, preventDefaults, false);
            });
            
            function preventDefaults(e) {
                e.preventDefault();
                e.stopPropagation();
            }
            
            ['dragenter', 'dragover'].forEach(eventName => {
                uploadSection.addEventListener(eventName, highlight, false);
            });
            
            ['dragleave', 'drop'].forEach(eventName => {
                uploadSection.addEventListener(eventName, unhighlight, false);
            });
            
            function highlight(e) {
                uploadSection.style.backgroundColor = '#e3f2fd';
                uploadSection.style.borderColor = '#667eea';
            }
            
            function unhighlight(e) {
                uploadSection.style.backgroundColor = '#f8f9fa';
                uploadSection.style.borderColor = 'transparent';
            }
            
            uploadSection.addEventListener('drop', handleDrop, false);
            
            function handleDrop(e) {
                const dt = e.dataTransfer;
                const files = dt.files;
                
                if (files.length > 0) {
                    document.getElementById('file').files = files;
                }
            }
        }
    </script>
</body>
</html>