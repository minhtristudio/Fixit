<?php
session_start();

// Cấu hình bảo mật
define('MASTER_KEY', hash('sha256', 'vDrive2024!@#$%^&*()_+{}[]|:;<>?,./' . $_SERVER['HTTP_HOST']));
define('UPLOAD_DIR', 'data/');
define('USERS_DIR', 'users/');
define('DB_FILE', 'vdrive.db');
define('MAX_FILE_SIZE', 500 * 1024 * 1024); // 500MB
define('DEFAULT_EXPIRE_HOURS', 168); // 1 tuần
define('FREE_STORAGE_LIMIT', 5 * 1024 * 1024 * 1024); // 5GB cho tài khoản free
define('PREMIUM_STORAGE_LIMIT', 100 * 1024 * 1024 * 1024); // 100GB cho premium

// Tạo các thư mục cần thiết
foreach ([UPLOAD_DIR, USERS_DIR] as $dir) {
    if (!file_exists($dir)) {
        mkdir($dir, 0755, true);
        file_put_contents($dir . '.htaccess', "Options -Indexes\nDeny from all");
    }
}

class UserManager {
    private $dbFile;
    
    public function __construct() {
        $this->dbFile = DB_FILE;
        $this->initDatabase();
    }
    
    private function initDatabase() {
        if (!file_exists($this->dbFile)) {
            $db = new SQLite3($this->dbFile);
            $db->exec("CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                storage_used INTEGER DEFAULT 0,
                storage_limit INTEGER DEFAULT " . FREE_STORAGE_LIMIT . ",
                is_premium INTEGER DEFAULT 0,
                created_at INTEGER DEFAULT " . time() . ",
                last_login INTEGER DEFAULT 0,
                two_factor_secret TEXT DEFAULT '',
                is_active INTEGER DEFAULT 1
            )");
            
            $db->exec("CREATE TABLE IF NOT EXISTS user_sessions (
                session_id TEXT PRIMARY KEY,
                user_id INTEGER,
                created_at INTEGER,
                expires_at INTEGER,
                ip_address TEXT,
                user_agent TEXT
            )");
            
            $db->exec("CREATE TABLE IF NOT EXISTS user_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                file_id TEXT UNIQUE,
                original_name TEXT,
                encrypted_name TEXT,
                file_size INTEGER,
                mime_type TEXT,
                upload_time INTEGER,
                expire_time INTEGER,
                download_count INTEGER DEFAULT 0,
                is_public INTEGER DEFAULT 0,
                password_protected INTEGER DEFAULT 0,
                public_token TEXT DEFAULT ''
            )");
            
            $db->close();
        }
    }
    
    public function register($username, $email, $password) {
        if (strlen($password) < 8) {
            return ['success' => false, 'message' => 'Mật khẩu phải có ít nhất 8 ký tự'];
        }
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['success' => false, 'message' => 'Email không hợp lệ'];
        }
        
        $db = new SQLite3($this->dbFile);
        
        // Kiểm tra username và email đã tồn tại
        $stmt = $db->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        $stmt->bindValue(1, $username);
        $stmt->bindValue(2, $email);
        $result = $stmt->execute();
        
        if ($result->fetchArray()) {
            $db->close();
            return ['success' => false, 'message' => 'Username hoặc email đã tồn tại'];
        }
        
        // Tạo tài khoản mới
        $salt = bin2hex(random_bytes(32));
        $passwordHash = hash('sha256', $password . $salt . MASTER_KEY);
        
        $stmt = $db->prepare("INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)");
        $stmt->bindValue(1, $username);
        $stmt->bindValue(2, $email);
        $stmt->bindValue(3, $passwordHash);
        $stmt->bindValue(4, $salt);
        
        if ($stmt->execute()) {
            $userId = $db->lastInsertRowID();
            
            // Tạo thư mục user
            $userDir = USERS_DIR . $userId . '/';
            if (!file_exists($userDir)) {
                mkdir($userDir, 0755, true);
            }
            
            $db->close();
            return ['success' => true, 'message' => 'Đăng ký thành công', 'user_id' => $userId];
        }
        
        $db->close();
        return ['success' => false, 'message' => 'Lỗi tạo tài khoản'];
    }
    
    public function login($username, $password, $remember = false) {
        $db = new SQLite3($this->dbFile);
        
        $stmt = $db->prepare("SELECT * FROM users WHERE (username = ? OR email = ?) AND is_active = 1");
        $stmt->bindValue(1, $username);
        $stmt->bindValue(2, $username);
        $result = $stmt->execute();
        $user = $result->fetchArray(SQLITE3_ASSOC);
        
        if (!$user) {
            $db->close();
            return ['success' => false, 'message' => 'Tài khoản không tồn tại'];
        }
        
        $passwordHash = hash('sha256', $password . $user['salt'] . MASTER_KEY);
        
        if ($passwordHash !== $user['password_hash']) {
            $db->close();
            return ['success' => false, 'message' => 'Mật khẩu không đúng'];
        }
        
        // Tạo session
        $sessionId = bin2hex(random_bytes(32));
        $expiresAt = time() + ($remember ? 30 * 24 * 3600 : 24 * 3600); // 30 ngày hoặc 1 ngày
        
        $stmt = $db->prepare("INSERT INTO user_sessions (session_id, user_id, created_at, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->bindValue(1, $sessionId);
        $stmt->bindValue(2, $user['id']);
        $stmt->bindValue(3, time());
        $stmt->bindValue(4, $expiresAt);
        $stmt->bindValue(5, $_SERVER['REMOTE_ADDR'] ?? '');
        $stmt->bindValue(6, $_SERVER['HTTP_USER_AGENT'] ?? '');
        $stmt->execute();
        
        // Cập nhật last_login
        $stmt = $db->prepare("UPDATE users SET last_login = ? WHERE id = ?");
        $stmt->bindValue(1, time());
        $stmt->bindValue(2, $user['id']);
        $stmt->execute();
        
        $db->close();
        
        // Lưu session
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['session_id'] = $sessionId;
        setcookie('vdrive_session', $sessionId, $expiresAt, '/', '', true, true);
        
        return ['success' => true, 'user' => $user];
    }
    
    public function logout() {
        if (isset($_SESSION['session_id'])) {
            $db = new SQLite3($this->dbFile);
            $stmt = $db->prepare("DELETE FROM user_sessions WHERE session_id = ?");
            $stmt->bindValue(1, $_SESSION['session_id']);
            $stmt->execute();
            $db->close();
        }
        
        session_destroy();
        setcookie('vdrive_session', '', time() - 3600, '/');
    }
    
    public function getCurrentUser() {
        if (!isset($_SESSION['user_id'])) {
            // Kiểm tra cookie
            if (isset($_COOKIE['vdrive_session'])) {
                $db = new SQLite3($this->dbFile);
                $stmt = $db->prepare("SELECT u.* FROM users u JOIN user_sessions s ON u.id = s.user_id WHERE s.session_id = ? AND s.expires_at > ?");
                $stmt->bindValue(1, $_COOKIE['vdrive_session']);
                $stmt->bindValue(2, time());
                $result = $stmt->execute();
                $user = $result->fetchArray(SQLITE3_ASSOC);
                
                if ($user) {
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['session_id'] = $_COOKIE['vdrive_session'];
                    $db->close();
                    return $user;
                }
                $db->close();
            }
            return null;
        }
        
        $db = new SQLite3($this->dbFile);
        $stmt = $db->prepare("SELECT * FROM users WHERE id = ? AND is_active = 1");
        $stmt->bindValue(1, $_SESSION['user_id']);
        $result = $stmt->execute();
        $user = $result->fetchArray(SQLITE3_ASSOC);
        $db->close();
        
        return $user;
    }
    
    public function updateStorageUsed($userId, $sizeChange) {
        $db = new SQLite3($this->dbFile);
        $stmt = $db->prepare("UPDATE users SET storage_used = storage_used + ? WHERE id = ?");
        $stmt->bindValue(1, $sizeChange);
        $stmt->bindValue(2, $userId);
        $stmt->execute();
        $db->close();
    }
    
    public function getStorageInfo($userId) {
        $db = new SQLite3($this->dbFile);
        $stmt = $db->prepare("SELECT storage_used, storage_limit, is_premium FROM users WHERE id = ?");
        $stmt->bindValue(1, $userId);
        $result = $stmt->execute();
        $info = $result->fetchArray(SQLITE3_ASSOC);
        $db->close();
        
        return $info;
    }
}

class SecureFileShare {
    private $userManager;
    
    public function __construct() {
        $this->userManager = new UserManager();
    }
    
    private function generateKey($password = '', $userId = '') {
        return hash('sha256', MASTER_KEY . $password . $userId . date('Y-m-d'));
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
    
    public function uploadFile($file, $password = '', $expireHours = DEFAULT_EXPIRE_HOURS, $userId = null, $isPublic = false) {
        if ($file['error'] !== UPLOAD_ERR_OK) {
            return ['success' => false, 'message' => 'Lỗi upload file'];
        }
        
        if ($file['size'] > MAX_FILE_SIZE) {
            return ['success' => false, 'message' => 'File quá lớn (max 500MB)'];
        }
        
        // Kiểm tra dung lượng storage nếu là user
        if ($userId) {
            $storageInfo = $this->userManager->getStorageInfo($userId);
            if ($storageInfo['storage_used'] + $file['size'] > $storageInfo['storage_limit']) {
                return ['success' => false, 'message' => 'Vượt quá giới hạn dung lượng'];
            }
        }
        
        $fileId = $this->generateFileId();
        $key = $this->generateKey($password, $userId);
        $originalName = $file['name'];
        
        // Đọc file content mà không làm mất chất lượng
        $fileContent = file_get_contents($file['tmp_name']);
        
        // Mã hóa metadata
        $metadata = [
            'original_name' => $originalName,
            'size' => $file['size'],
            'type' => $file['type'],
            'upload_time' => time(),
            'expire_time' => time() + ($expireHours * 3600),
            'password_protected' => !empty($password),
            'user_id' => $userId,
            'is_public' => $isPublic
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
        
        $filePath = ($userId ? USERS_DIR . $userId . '/' : UPLOAD_DIR) . $storedFilename;
        if (file_put_contents($filePath, serialize($fileData))) {
            // Lưu vào database nếu là user
            if ($userId) {
                $publicToken = $isPublic ? bin2hex(random_bytes(16)) : '';
                $db = new SQLite3(DB_FILE);
                $stmt = $db->prepare("INSERT INTO user_files (user_id, file_id, original_name, encrypted_name, file_size, mime_type, upload_time, expire_time, is_public, password_protected, public_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                $stmt->bindValue(1, $userId);
                $stmt->bindValue(2, $fileId);
                $stmt->bindValue(3, $originalName);
                $stmt->bindValue(4, $storedFilename);
                $stmt->bindValue(5, $file['size']);
                $stmt->bindValue(6, $file['type']);
                $stmt->bindValue(7, time());
                $stmt->bindValue(8, $metadata['expire_time']);
                $stmt->bindValue(9, $isPublic ? 1 : 0);
                $stmt->bindValue(10, !empty($password) ? 1 : 0);
                $stmt->bindValue(11, $publicToken);
                $stmt->execute();
                $db->close();
                
                // Cập nhật storage used
                $this->userManager->updateStorageUsed($userId, $file['size']);
            } else {
                // Lưu mapping cho guest users
                $mappingFile = UPLOAD_DIR . '.mapping';
                $mapping = file_exists($mappingFile) ? unserialize(file_get_contents($mappingFile)) : [];
                $mapping[$fileId] = $storedFilename;
                file_put_contents($mappingFile, serialize($mapping));
            }
            
            $downloadLink = $_SERVER['REQUEST_URI'];
            if ($userId && $isPublic && !empty($publicToken)) {
                $downloadLink .= '?public=' . $publicToken;
            } else {
                $downloadLink .= '?download=' . $fileId;
            }
            
            return [
                'success' => true,
                'file_id' => $fileId,
                'download_link' => $downloadLink,
                'public_token' => $publicToken ?? '',
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
    
    public function downloadFile($fileId, $password = '', $publicToken = '') {
        $filePath = '';
        $metadata = null;
        $userId = null;
        
        // Xử lý public download
        if (!empty($publicToken)) {
            $db = new SQLite3(DB_FILE);
            $stmt = $db->prepare("SELECT * FROM user_files WHERE public_token = ? AND is_public = 1");
            $stmt->bindValue(1, $publicToken);
            $result = $stmt->execute();
            $fileInfo = $result->fetchArray(SQLITE3_ASSOC);
            $db->close();
            
            if (!$fileInfo) {
                return ['success' => false, 'message' => 'Link public không hợp lệ'];
            }
            
            $filePath = USERS_DIR . $fileInfo['user_id'] . '/' . $fileInfo['encrypted_name'];
            $userId = $fileInfo['user_id'];
            $fileId = $fileInfo['file_id'];
        } else {
            // Kiểm tra trong database trước (user files)
            $db = new SQLite3(DB_FILE);
            $stmt = $db->prepare("SELECT * FROM user_files WHERE file_id = ?");
            $stmt->bindValue(1, $fileId);
            $result = $stmt->execute();
            $fileInfo = $result->fetchArray(SQLITE3_ASSOC);
            
            if ($fileInfo) {
                $filePath = USERS_DIR . $fileInfo['user_id'] . '/' . $fileInfo['encrypted_name'];
                $userId = $fileInfo['user_id'];
                
                // Cập nhật download count
                $stmt = $db->prepare("UPDATE user_files SET download_count = download_count + 1 WHERE id = ?");
                $stmt->bindValue(1, $fileInfo['id']);
                $stmt->execute();
            } else {
                // Kiểm tra guest files
                $mappingFile = UPLOAD_DIR . '.mapping';
                if (!file_exists($mappingFile)) {
                    $db->close();
                    return ['success' => false, 'message' => 'File không tồn tại'];
                }
                
                $mapping = unserialize(file_get_contents($mappingFile));
                if (!isset($mapping[$fileId])) {
                    $db->close();
                    return ['success' => false, 'message' => 'File không tồn tại'];
                }
                
                $filePath = UPLOAD_DIR . $mapping[$fileId];
            }
            $db->close();
        }
        
        if (!file_exists($filePath)) {
            return ['success' => false, 'message' => 'File không tồn tại'];
        }
        
        $key = $this->generateKey($password, $userId);
        $fileData = unserialize(file_get_contents($filePath));
        
        // Giải mã metadata
        $metadataJson = $this->decrypt($fileData['metadata'], $key);
        if (!$metadataJson) {
            return ['success' => false, 'message' => 'Sai mật khẩu hoặc file bị hỏng'];
        }
        
        $metadata = json_decode($metadataJson, true);
        
        // Kiểm tra thời gian hết hạn
        if (time() > $metadata['expire_time']) {
            $this->deleteFile($fileId, $userId);
            return ['success' => false, 'message' => 'File đã hết hạn'];
        }
        
        // Kiểm tra mật khẩu cho file không public
        if ($metadata['password_protected'] && empty($password) && empty($publicToken)) {
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
    
    public function deleteFile($fileId, $userId = null) {
        // Xóa file của user
        if ($userId) {
            $db = new SQLite3(DB_FILE);
            $stmt = $db->prepare("SELECT * FROM user_files WHERE file_id = ? AND user_id = ?");
            $stmt->bindValue(1, $fileId);
            $stmt->bindValue(2, $userId);
            $result = $stmt->execute();
            $fileInfo = $result->fetchArray(SQLITE3_ASSOC);
            
            if ($fileInfo) {
                $filePath = USERS_DIR . $userId . '/' . $fileInfo['encrypted_name'];
                if (file_exists($filePath)) {
                    unlink($filePath);
                }
                
                // Cập nhật storage used
                $this->userManager->updateStorageUsed($userId, -$fileInfo['file_size']);
                
                // Xóa record
                $stmt = $db->prepare("DELETE FROM user_files WHERE id = ?");
                $stmt->bindValue(1, $fileInfo['id']);
                $stmt->execute();
                
                $db->close();
                return true;
            }
            $db->close();
        } else {
            // Xóa guest file
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
        }
        return false;
    }
    
    public function getUserFiles($userId, $limit = 50, $offset = 0) {
        $db = new SQLite3(DB_FILE);
        $stmt = $db->prepare("SELECT * FROM user_files WHERE user_id = ? ORDER BY upload_time DESC LIMIT ? OFFSET ?");
        $stmt->bindValue(1, $userId);
        $stmt->bindValue(2, $limit);
        $stmt->bindValue(3, $offset);
        $result = $stmt->execute();
        
        $files = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $files[] = $row;
        }
        
        $db->close();
        return $files;
    }
    
    public function togglePublicAccess($fileId, $userId) {
        $db = new SQLite3(DB_FILE);
        $stmt = $db->prepare("SELECT * FROM user_files WHERE file_id = ? AND user_id = ?");
        $stmt->bindValue(1, $fileId);
        $stmt->bindValue(2, $userId);
        $result = $stmt->execute();
        $fileInfo = $result->fetchArray(SQLITE3_ASSOC);
        
        if ($fileInfo) {
            $newPublicStatus = $fileInfo['is_public'] ? 0 : 1;
            $publicToken = $newPublicStatus ? bin2hex(random_bytes(16)) : '';
            
            $stmt = $db->prepare("UPDATE user_files SET is_public = ?, public_token = ? WHERE id = ?");
            $stmt->bindValue(1, $newPublicStatus);
            $stmt->bindValue(2, $publicToken);
            $stmt->bindValue(3, $fileInfo['id']);
            $stmt->execute();
            
            $db->close();
            return ['success' => true, 'is_public' => $newPublicStatus, 'public_token' => $publicToken];
        }
        
        $db->close();
        return ['success' => false];
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

$userManager = new UserManager();
$fileShare = new SecureFileShare();
$currentUser = $userManager->getCurrentUser();

// Xử lý các request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'register':
                $result = $userManager->register($_POST['username'], $_POST['email'], $_POST['password']);
                echo json_encode($result);
                break;
                
            case 'login':
                $result = $userManager->login($_POST['username'], $_POST['password'], isset($_POST['remember']));
                echo json_encode($result);
                break;
                
            case 'logout':
                $userManager->logout();
                echo json_encode(['success' => true]);
                break;
                
            case 'upload':
                if (isset($_FILES['file'])) {
                    $password = $_POST['password'] ?? '';
                    $expireHours = intval($_POST['expire_hours'] ?? DEFAULT_EXPIRE_HOURS);
                    $isPublic = isset($_POST['is_public']) && $_POST['is_public'] === '1';
                    $userId = $currentUser ? $currentUser['id'] : null;
                    
                    $result = $fileShare->uploadFile($_FILES['file'], $password, $expireHours, $userId, $isPublic);
                    echo json_encode($result);
                } else {
                    echo json_encode(['success' => false, 'message' => 'Không có file được chọn']);
                }
                break;
                
            case 'delete':
                $fileId = $_POST['file_id'] ?? '';
                $userId = $currentUser ? $currentUser['id'] : null;
                $result = $fileShare->deleteFile($fileId, $userId);
                echo json_encode(['success' => $result]);
                break;
                
            case 'toggle_public':
                if ($currentUser) {
                    $fileId = $_POST['file_id'] ?? '';
                    $result = $fileShare->togglePublicAccess($fileId, $currentUser['id']);
                    echo json_encode($result);
                } else {
                    echo json_encode(['success' => false, 'message' => 'Cần đăng nhập']);
                }
                break;
                
            case 'get_files':
                if ($currentUser) {
                    $files = $fileShare->getUserFiles($currentUser['id']);
                    echo json_encode(['success' => true, 'files' => $files]);
                } else {
                    echo json_encode(['success' => false, 'message' => 'Cần đăng nhập']);
                }
                break;
        }
    }
    exit;
}

// Xử lý download
if (isset($_GET['download']) || isset($_GET['public'])) {
    $fileId = $_GET['download'] ?? '';
    $publicToken = $_GET['public'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
        $result = $fileShare->downloadFile($fileId, $password, $publicToken);
        
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
        $result = $fileShare->downloadFile($fileId, '', $publicToken);
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

function formatBytes($size, $precision = 2) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    for ($i = 0; $size > 1024 && $i < count($units) - 1; $i++) {
        $size /= 1024;
    }
    return round($size, $precision) . ' ' . $units[$i];
}
?>

<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>vDrive - Chia sẻ file siêu an toàn</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
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
            margin: 0;
            padding: 0;
        }
        
        .navbar {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 15px 0;
            box-shadow: 0 2px 20px rgba(0, 0, 0, 0.1);
            position: fixed;
            top: 0;
            width: 100%;
            z-index: 1000;
        }
        
        .nav-container {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0 20px;
        }
        
        .logo {
            font-size: 1.8em;
            font-weight: bold;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .nav-menu {
            display: flex;
            gap: 20px;
            align-items: center;
        }
        
        .nav-item {
            color: #333;
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 8px;
            transition: all 0.3s;
        }
        
        .nav-item:hover {
            background: rgba(102, 126, 234, 0.1);
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .storage-bar {
            width: 100px;
            height: 4px;
            background: #e1e5e9;
            border-radius: 2px;
            overflow: hidden;
        }
        
        .storage-progress {
            height: 100%;
            background: linear-gradient(45deg, #667eea, #764ba2);
            transition: width 0.3s;
        }
        
        .main-content {
            margin-top: 80px;
            padding: 20px;
            max-width: 1200px;
            margin-left: auto;
            margin-right: auto;
        }
        
        .container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 30px;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
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
        
        .file-manager-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .files-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .file-item {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            border: 2px solid #e1e5e9;
            transition: all 0.3s;
        }
        
        .file-item:hover {
            border-color: #667eea;
            transform: translateY(-2px);
        }
        
        .file-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .file-name {
            font-weight: 600;
            color: #333;
            word-break: break-word;
        }
        
        .file-actions {
            display: flex;
            gap: 10px;
        }
        
        .btn-small {
            padding: 6px 12px;
            font-size: 0.9em;
            border-radius: 6px;
            border: none;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-secondary {
            background: #6c757d;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-secondary:hover {
            background: #5a6268;
            transform: translateY(-1px);
        }
        
        .btn-danger {
            background: #dc3545;
            color: white;
        }
        
        .btn-danger:hover {
            background: #c82333;
        }
        
        .btn-success {
            background: #28a745;
            color: white;
        }
        
        .btn-success:hover {
            background: #218838;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 2000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(5px);
        }
        
        .modal-content {
            background: white;
            margin: 10% auto;
            padding: 30px;
            border-radius: 15px;
            width: 90%;
            max-width: 500px;
            position: relative;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
        }
        
        .close {
            position: absolute;
            right: 15px;
            top: 15px;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            color: #aaa;
        }
        
        .close:hover {
            color: #000;
        }
        
        .auth-tabs {
            display: flex;
            margin-bottom: 20px;
            background: #f8f9fa;
            border-radius: 8px;
            padding: 4px;
        }
        
        .auth-tab {
            flex: 1;
            text-align: center;
            padding: 10px;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .auth-tab.active {
            background: #667eea;
            color: white;
        }
        
        .checkbox-label {
            display: flex;
            align-items: center;
            gap: 10px;
            cursor: pointer;
        }
        
        .checkbox-label input[type="checkbox"] {
            width: auto;
        }
        
        .guest-note {
            background: #e3f2fd;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            color: #1976d2;
        }
        
        .public-indicator {
            color: #28a745;
            font-weight: bold;
        }
        
        .private-indicator {
            color: #dc3545;
            font-weight: bold;
        }
        
        @media (max-width: 768px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
            
            .nav-container {
                flex-direction: column;
                gap: 15px;
            }
            
            .user-info {
                flex-direction: column;
                gap: 10px;
            }
            
            .files-grid {
                grid-template-columns: 1fr;
            }
            
            .main-content {
                margin-top: 120px;
            }
        }
    </style>
</head>
<body>
    <!-- Navigation Bar -->
    <nav class="navbar">
        <div class="nav-container">
            <div class="logo">
                <i class="fas fa-cloud"></i> vDrive
            </div>
            <div class="nav-menu">
                <?php if ($currentUser): ?>
                    <div class="user-info">
                        <span>Xin chào, <strong><?php echo htmlspecialchars($currentUser['username']); ?></strong></span>
                        <?php 
                        $storageInfo = $userManager->getStorageInfo($currentUser['id']);
                        $usagePercent = ($storageInfo['storage_used'] / $storageInfo['storage_limit']) * 100;
                        ?>
                        <div class="storage-info">
                            <small><?php echo formatBytes($storageInfo['storage_used']); ?> / <?php echo formatBytes($storageInfo['storage_limit']); ?></small>
                            <div class="storage-bar">
                                <div class="storage-progress" style="width: <?php echo $usagePercent; ?>%"></div>
                            </div>
                        </div>
                        <a href="#" class="nav-item" onclick="logout()">
                            <i class="fas fa-sign-out-alt"></i> Đăng xuất
                        </a>
                    </div>
                <?php else: ?>
                    <a href="#" class="nav-item" onclick="showAuthModal('login')">
                        <i class="fas fa-sign-in-alt"></i> Đăng nhập
                    </a>
                    <a href="#" class="nav-item" onclick="showAuthModal('register')">
                        <i class="fas fa-user-plus"></i> Đăng ký
                    </a>
                <?php endif; ?>
            </div>
        </div>
    </nav>

    <div class="main-content">
        <?php if (isset($_GET['download']) || isset($_GET['public'])): ?>
            <!-- Download Page -->
            <div class="container">
                <div class="header">
                    <h2><i class="fas fa-download"></i> Tải xuống file</h2>
                </div>
                
                <?php if (isset($needPassword)): ?>
                    <form method="POST">
                        <div class="form-group">
                            <label for="password"><i class="fas fa-key"></i> Nhập mật khẩu để tải file:</label>
                            <input type="password" id="password" name="password" required>
                        </div>
                        <button type="submit" class="btn">
                            <i class="fas fa-download"></i> Tải xuống
                        </button>
                    </form>
                <?php elseif (isset($error)): ?>
                    <div class="result error" style="display: block;">
                        <i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?>
                    </div>
                    <a href="<?php echo $_SERVER['PHP_SELF']; ?>" class="btn" style="display: inline-block; text-decoration: none; text-align: center; margin-top: 15px;">
                        <i class="fas fa-home"></i> Quay lại
                    </a>
                <?php endif; ?>
            </div>
        <?php else: ?>
            <!-- Main Dashboard -->
            <div class="container">
                <div class="header">
                    <h1><i class="fas fa-cloud"></i> vDrive</h1>
                    <p>Chia sẻ file với mã hóa AES-256 siêu an toàn</p>
                </div>
                
                <div class="security-info">
                    <h3><i class="fas fa-shield-alt"></i> Bảo mật tuyệt đối</h3>
                    <p>Files của bạn được mã hóa với chuẩn quân sự AES-256</p>
                    <div class="security-features">
                        <div class="feature"><i class="fas fa-lock"></i> Mã hóa end-to-end</div>
                        <div class="feature"><i class="fas fa-user-secret"></i> Ẩn danh hoàn toàn</div>
                        <div class="feature"><i class="fas fa-clock"></i> Tự động xóa</div>
                        <div class="feature"><i class="fas fa-ban"></i> Hosting không thể đọc</div>
                    </div>
                </div>
            </div>

            <?php if ($currentUser): ?>
                <!-- Logged in user dashboard -->
                <div class="dashboard-grid">
                    <!-- Upload Section -->
                    <div class="card">
                        <h3><i class="fas fa-cloud-upload-alt"></i> Upload File</h3>
                        <form id="uploadForm" enctype="multipart/form-data">
                            <div class="form-group">
                                <label for="file"><i class="fas fa-file"></i> Chọn file (max 500MB):</label>
                                <input type="file" id="file" name="file" required>
                            </div>
                            
                            <div class="form-group">
                                <label for="password"><i class="fas fa-key"></i> Mật khẩu bảo vệ (tùy chọn):</label>
                                <input type="password" id="password" name="password" placeholder="Để trống nếu không cần mật khẩu">
                            </div>
                            
                            <div class="form-group">
                                <label for="expire_hours"><i class="fas fa-clock"></i> Thời gian tự động xóa:</label>
                                <select id="expire_hours" name="expire_hours">
                                    <option value="1">1 giờ</option>
                                    <option value="6">6 giờ</option>
                                    <option value="24">24 giờ</option>
                                    <option value="72">3 ngày</option>
                                    <option value="168" selected>1 tuần</option>
                                </select>
                            </div>
                            
                            <div class="form-group">
                                <label class="checkbox-label">
                                    <input type="checkbox" id="is_public" name="is_public" value="1">
                                    <i class="fas fa-globe"></i> Cho phép tải xuống công khai (không cần đăng nhập)
                                </label>
                            </div>
                            
                            <button type="submit" class="btn">
                                <i class="fas fa-cloud-upload-alt"></i> Upload File
                            </button>
                            <div class="progress">
                                <div class="progress-bar"></div>
                            </div>
                        </form>
                        
                        <div id="uploadResult" class="result"></div>
                    </div>
                    
                    <!-- Quick Download -->
                    <div class="card">
                        <h3><i class="fas fa-download"></i> Tải xuống nhanh</h3>
                        <div class="form-group">
                            <label for="fileId"><i class="fas fa-link"></i> Nhập File ID hoặc link:</label>
                            <input type="text" id="fileId" placeholder="Nhập ID file hoặc dán link đầy đủ">
                        </div>
                        <button onclick="downloadFile()" class="btn">
                            <i class="fas fa-download"></i> Tải xuống
                        </button>
                    </div>
                </div>
                
                <!-- File Manager -->
                <div class="container">
                    <div class="file-manager-header">
                        <h3><i class="fas fa-folder-open"></i> Quản lý file của bạn</h3>
                        <button onclick="loadUserFiles()" class="btn-secondary">
                            <i class="fas fa-sync-alt"></i> Làm mới
                        </button>
                    </div>
                    <div id="filesList" class="files-grid">
                        <!-- Files will be loaded here -->
                    </div>
                </div>
            <?php else: ?>
                <!-- Guest user interface -->
                <div class="dashboard-grid">
                    <div class="card">
                        <h3><i class="fas fa-cloud-upload-alt"></i> Upload File (Guest)</h3>
                        <p class="guest-note">
                            <i class="fas fa-info-circle"></i> 
                            Bạn đang sử dụng chế độ khách. Đăng ký để có nhiều tính năng hơn!
                        </p>
                        <form id="uploadForm" enctype="multipart/form-data">
                            <div class="form-group">
                                <label for="file"><i class="fas fa-file"></i> Chọn file (max 500MB):</label>
                                <input type="file" id="file" name="file" required>
                            </div>
                            
                            <div class="form-group">
                                <label for="password"><i class="fas fa-key"></i> Mật khẩu bảo vệ (tùy chọn):</label>
                                <input type="password" id="password" name="password" placeholder="Để trống nếu không cần mật khẩu">
                            </div>
                            
                            <div class="form-group">
                                <label for="expire_hours"><i class="fas fa-clock"></i> Thời gian tự động xóa:</label>
                                <select id="expire_hours" name="expire_hours">
                                    <option value="1">1 giờ</option>
                                    <option value="6">6 giờ</option>
                                    <option value="24" selected>24 giờ</option>
                                    <option value="72">3 ngày</option>
                                </select>
                            </div>
                            
                            <button type="submit" class="btn">
                                <i class="fas fa-cloud-upload-alt"></i> Upload File
                            </button>
                            <div class="progress">
                                <div class="progress-bar"></div>
                            </div>
                        </form>
                        
                        <div id="uploadResult" class="result"></div>
                    </div>
                    
                    <div class="card">
                        <h3><i class="fas fa-download"></i> Tải xuống file</h3>
                        <div class="form-group">
                            <label for="fileId"><i class="fas fa-link"></i> Nhập File ID hoặc link:</label>
                            <input type="text" id="fileId" placeholder="Nhập ID file hoặc dán link đầy đủ">
                        </div>
                        <button onclick="downloadFile()" class="btn">
                            <i class="fas fa-download"></i> Tải xuống
                        </button>
                    </div>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <!-- Auth Modal -->
    <div id="authModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeAuthModal()">&times;</span>
            <div id="authModalContent">
                <!-- Auth forms will be loaded here -->
            </div>
        </div>
    </div>


    
    <script>
        // Authentication functions
        function showAuthModal(type) {
            const modal = document.getElementById('authModal');
            const modalContent = document.getElementById('authModalContent');
            
            if (type === 'login') {
                modalContent.innerHTML = `
                    <div class="auth-tabs">
                        <div class="auth-tab active" onclick="showAuthForm('login')">Đăng nhập</div>
                        <div class="auth-tab" onclick="showAuthForm('register')">Đăng ký</div>
                    </div>
                    <div id="loginForm">
                        <h3><i class="fas fa-sign-in-alt"></i> Đăng nhập</h3>
                        <form id="authLoginForm">
                            <div class="form-group">
                                <label><i class="fas fa-user"></i> Username hoặc Email:</label>
                                <input type="text" name="username" required>
                            </div>
                            <div class="form-group">
                                <label><i class="fas fa-key"></i> Mật khẩu:</label>
                                <input type="password" name="password" required>
                            </div>
                            <div class="form-group">
                                <label class="checkbox-label">
                                    <input type="checkbox" name="remember">
                                    <span>Ghi nhớ đăng nhập</span>
                                </label>
                            </div>
                            <button type="submit" class="btn">
                                <i class="fas fa-sign-in-alt"></i> Đăng nhập
                            </button>
                        </form>
                    </div>
                `;
            } else if (type === 'register') {
                modalContent.innerHTML = `
                    <div class="auth-tabs">
                        <div class="auth-tab" onclick="showAuthForm('login')">Đăng nhập</div>
                        <div class="auth-tab active" onclick="showAuthForm('register')">Đăng ký</div>
                    </div>
                    <div id="registerForm">
                        <h3><i class="fas fa-user-plus"></i> Đăng ký tài khoản</h3>
                        <form id="authRegisterForm">
                            <div class="form-group">
                                <label><i class="fas fa-user"></i> Username:</label>
                                <input type="text" name="username" required>
                            </div>
                            <div class="form-group">
                                <label><i class="fas fa-envelope"></i> Email:</label>
                                <input type="email" name="email" required>
                            </div>
                            <div class="form-group">
                                <label><i class="fas fa-key"></i> Mật khẩu:</label>
                                <input type="password" name="password" required minlength="8">
                            </div>
                            <button type="submit" class="btn">
                                <i class="fas fa-user-plus"></i> Đăng ký
                            </button>
                        </form>
                    </div>
                `;
            }
            
            modal.style.display = 'block';
            setupAuthForms();
        }
        
        function showAuthForm(type) {
            showAuthModal(type);
        }
        
        function closeAuthModal() {
            document.getElementById('authModal').style.display = 'none';
        }
        
        function setupAuthForms() {
            const loginForm = document.getElementById('authLoginForm');
            const registerForm = document.getElementById('authRegisterForm');
            
            if (loginForm) {
                loginForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    const formData = new FormData(this);
                    formData.append('action', 'login');
                    
                    fetch('', {
                        method: 'POST',
                        body: formData
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            location.reload();
                        } else {
                            alert('❌ ' + data.message);
                        }
                    });
                });
            }
            
            if (registerForm) {
                registerForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    const formData = new FormData(this);
                    formData.append('action', 'register');
                    
                    fetch('', {
                        method: 'POST',
                        body: formData
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            alert('✅ ' + data.message);
                            closeAuthModal();
                            showAuthModal('login');
                        } else {
                            alert('❌ ' + data.message);
                        }
                    });
                });
            }
        }
        
        function logout() {
            if (confirm('Bạn có chắc muốn đăng xuất?')) {
                const formData = new FormData();
                formData.append('action', 'logout');
                
                fetch('', {
                    method: 'POST',
                    body: formData
                })
                .then(() => {
                    location.reload();
                });
            }
        }
        
        // File upload functionality
        function setupUploadForm() {
            const uploadForm = document.getElementById('uploadForm');
            if (!uploadForm) return;
            
            uploadForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const formData = new FormData();
                const fileInput = document.getElementById('file');
                const passwordInput = document.getElementById('password');
                const expireInput = document.getElementById('expire_hours');
                const isPublicInput = document.getElementById('is_public');
                
                if (!fileInput.files[0]) {
                    showResult('error', '<i class="fas fa-exclamation-triangle"></i> Vui lòng chọn file');
                    return;
                }
                
                formData.append('action', 'upload');
                formData.append('file', fileInput.files[0]);
                formData.append('password', passwordInput.value);
                formData.append('expire_hours', expireInput.value);
                if (isPublicInput && isPublicInput.checked) {
                    formData.append('is_public', '1');
                }
                
                // Show progress
                const progress = document.querySelector('.progress');
                const progressBar = document.querySelector('.progress-bar');
                progress.style.display = 'block';
                
                const xhr = new XMLHttpRequest();
                
                xhr.upload.addEventListener('progress', function(e) {
                    if (e.lengthComputable) {
                        const percentComplete = (e.loaded / e.total) * 100;
                        progressBar.style.width = percentComplete + '%';
                    }
                });
                
                xhr.addEventListener('load', function() {
                    progress.style.display = 'none';
                    progressBar.style.width = '0%';
                    
                    try {
                        const response = JSON.parse(xhr.responseText);
                        if (response.success) {
                            let resultHtml = `
                                <i class="fas fa-check-circle"></i> Upload thành công!<br>
                                <strong>File ID:</strong> ${response.file_id}<br>
                                <strong>Hết hạn:</strong> ${response.expire_time}<br>
                            `;
                            
                            if (response.public_token) {
                                resultHtml += `
                                    <div class="download-link">
                                        <strong><i class="fas fa-globe"></i> Link công khai:</strong><br>
                                        <a href="${response.download_link}" target="_blank">${response.download_link}</a>
                                    </div>
                                `;
                            } else {
                                resultHtml += `
                                    <div class="download-link">
                                        <strong><i class="fas fa-link"></i> Link tải:</strong><br>
                                        <a href="${response.download_link}" target="_blank">${response.download_link}</a>
                                    </div>
                                `;
                            }
                            
                            showResult('success', resultHtml);
                            uploadForm.reset();
                            
                            // Refresh file list if user is logged in
                            if (typeof loadUserFiles === 'function') {
                                setTimeout(loadUserFiles, 1000);
                            }
                        } else {
                            showResult('error', '<i class="fas fa-exclamation-triangle"></i> ' + response.message);
                        }
                    } catch (error) {
                        showResult('error', '<i class="fas fa-exclamation-triangle"></i> Lỗi xử lý phản hồi từ server');
                    }
                });
                
                xhr.addEventListener('error', function() {
                    progress.style.display = 'none';
                    showResult('error', '<i class="fas fa-exclamation-triangle"></i> Lỗi mạng, vui lòng thử lại');
                });
                
                xhr.open('POST', '');
                xhr.send(formData);
            });
        }
        
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
        
        // File management functions
        function loadUserFiles() {
            const formData = new FormData();
            formData.append('action', 'get_files');
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    displayUserFiles(data.files);
                }
            });
        }
        
        function displayUserFiles(files) {
            const filesList = document.getElementById('filesList');
            if (!filesList) return;
            
            if (files.length === 0) {
                filesList.innerHTML = '<p style="text-align: center; color: #666;"><i class="fas fa-folder-open"></i> Chưa có file nào</p>';
                return;
            }
            
            filesList.innerHTML = files.map(file => {
                const isExpired = new Date(file.expire_time * 1000) < new Date();
                const publicStatus = file.is_public ? 
                    '<span class="public-indicator"><i class="fas fa-globe"></i> Công khai</span>' : 
                    '<span class="private-indicator"><i class="fas fa-lock"></i> Riêng tư</span>';
                
                return `
                    <div class="file-item">
                        <div class="file-header">
                            <div class="file-name">
                                <i class="fas fa-file"></i> ${file.original_name}
                            </div>
                            <div class="file-actions">
                                <button class="btn-small btn-success" onclick="downloadUserFile('${file.file_id}')">
                                    <i class="fas fa-download"></i>
                                </button>
                                <button class="btn-small btn-secondary" onclick="togglePublic('${file.file_id}')">
                                    <i class="fas fa-${file.is_public ? 'lock' : 'globe'}"></i>
                                </button>
                                <button class="btn-small btn-danger" onclick="deleteUserFile('${file.file_id}')">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </div>
                        </div>
                        <div class="file-info">
                            <small>
                                <strong>Kích thước:</strong> ${formatBytes(file.file_size)}<br>
                                <strong>Tải lần:</strong> ${file.download_count}<br>
                                <strong>Hết hạn:</strong> ${new Date(file.expire_time * 1000).toLocaleString()}<br>
                                <strong>Trạng thái:</strong> ${publicStatus}
                                ${file.password_protected ? ' <i class="fas fa-key" title="Có mật khẩu"></i>' : ''}
                                ${isExpired ? ' <span style="color: red;"><i class="fas fa-exclamation-triangle"></i> Đã hết hạn</span>' : ''}
                            </small>
                        </div>
                        ${file.is_public && file.public_token ? `
                            <div class="public-link" style="margin-top: 10px;">
                                <small><strong>Link công khai:</strong></small><br>
                                <input type="text" value="${window.location.origin}${window.location.pathname}?public=${file.public_token}" 
                                       onclick="this.select()" readonly style="width: 100%; font-size: 0.8em;">
                            </div>
                        ` : ''}
                    </div>
                `;
            }).join('');
        }
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        function downloadUserFile(fileId) {
            window.location.href = '?download=' + fileId;
        }
        
        function deleteUserFile(fileId) {
            if (confirm('Bạn có chắc muốn xóa file này?')) {
                const formData = new FormData();
                formData.append('action', 'delete');
                formData.append('file_id', fileId);
                
                fetch('', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        loadUserFiles();
                    } else {
                        alert('Không thể xóa file');
                    }
                });
            }
        }
        
        function togglePublic(fileId) {
            const formData = new FormData();
            formData.append('action', 'toggle_public');
            formData.append('file_id', fileId);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    loadUserFiles();
                } else {
                    alert('Không thể thay đổi trạng thái công khai');
                }
            });
        }
        
        function downloadFile() {
            const fileIdInput = document.getElementById('fileId');
            let fileId = fileIdInput.value.trim();
            
            if (!fileId) {
                alert('<i class="fas fa-exclamation-triangle"></i> Vui lòng nhập File ID hoặc link');
                return;
            }
            
            // Extract file ID from full URL if needed
            if (fileId.includes('download=')) {
                const match = fileId.match(/download=([a-f0-9]+)/);
                if (match) {
                    fileId = match[1];
                }
            } else if (fileId.includes('public=')) {
                // Handle public links
                window.location.href = fileId;
                return;
            }
            
            window.location.href = '?download=' + fileId;
        }
        
        // Initialization
        document.addEventListener('DOMContentLoaded', function() {
            setupUploadForm();
            
            // Load user files if logged in
            if (document.getElementById('filesList')) {
                loadUserFiles();
            }
            
            // Setup drag and drop
            setupDragAndDrop();
            
            // Close modal when clicking outside
            window.addEventListener('click', function(event) {
                const modal = document.getElementById('authModal');
                if (event.target === modal) {
                    closeAuthModal();
                }
            });
        });
        
        function setupDragAndDrop() {
            const uploadCards = document.querySelectorAll('.card');
            
            uploadCards.forEach(card => {
                if (card.querySelector('#file')) {
                    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                        card.addEventListener(eventName, preventDefaults, false);
                    });
                    
                    ['dragenter', 'dragover'].forEach(eventName => {
                        card.addEventListener(eventName, () => highlight(card), false);
                    });
                    
                    ['dragleave', 'drop'].forEach(eventName => {
                        card.addEventListener(eventName, () => unhighlight(card), false);
                    });
                    
                    card.addEventListener('drop', handleDrop, false);
                }
            });
            
            function preventDefaults(e) {
                e.preventDefault();
                e.stopPropagation();
            }
            
            function highlight(element) {
                element.style.backgroundColor = '#e3f2fd';
                element.style.borderColor = '#667eea';
                element.style.transform = 'scale(1.02)';
            }
            
            function unhighlight(element) {
                element.style.backgroundColor = '';
                element.style.borderColor = '';
                element.style.transform = '';
            }
            
            function handleDrop(e) {
                const dt = e.dataTransfer;
                const files = dt.files;
                
                if (files.length > 0) {
                    const fileInput = document.getElementById('file');
                    if (fileInput) {
                        fileInput.files = files;
                        
                        // Trigger change event to show file name
                        const event = new Event('change', { bubbles: true });
                        fileInput.dispatchEvent(event);
                    }
                }
            }
        }
        
        // Auto refresh file list every 30 seconds
        setInterval(function() {
            if (document.getElementById('filesList') && typeof loadUserFiles === 'function') {
                loadUserFiles();
            }
        }, 30000);
    </script>
</body>
</html>