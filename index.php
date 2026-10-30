<?php
declare(strict_types=1);

session_set_cookie_params([
    'httponly' => true,
    'samesite' => 'Lax',
    'secure' => !empty($_SERVER['HTTPS']),
]);
session_start();

error_reporting(E_ALL);
ini_set('display_errors', '1'); // Set to 0 in production.

const APP_NAME = 'CityDate';
const DB_FILE = __DIR__ . '/dating.sqlite';
const KEY_FILE = __DIR__ . '/.dating.key';
const MESSAGE_TTL_DAYS = 100;
const USER_TTL_YEARS = 6;
const ONLINE_SECONDS = 900; // 15 minutes.
const ROOM_PRESENCE_SECONDS = 120;

if (!extension_loaded('sodium')) {
    exit('The sodium extension is required.');
}
if (!extension_loaded('pdo_sqlite')) {
    exit('The pdo_sqlite extension is required.');
}

function load_key(): string
{
    $env = getenv('DATING_KEY');
    if ($env !== false && $env !== '') {
        $key = base64_decode($env, true);
        if ($key === false || strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            exit('DATING_KEY must be a base64-encoded 32-byte key.');
        }
        return $key;
    }

    if (is_file(KEY_FILE)) {
        $key = file_get_contents(KEY_FILE);
        if ($key === false || strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            exit('Invalid key file.');
        }
        return $key;
    }

    $key = sodium_crypto_secretbox_keygen();
    if (file_put_contents(KEY_FILE, $key) === false) {
        exit('Unable to create key file.');
    }
    @chmod(KEY_FILE, 0600);

    return $key;
}

$GLOBALS['KEY'] = load_key();

function e(?string $value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function redirect(string $url): void
{
    header('Location: ' . $url);
    exit;
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf" value="' . e(csrf_token()) . '">';
}

function verify_csrf(): void
{
    if (!hash_equals(csrf_token(), $_POST['csrf'] ?? '')) {
        http_response_code(400);
        exit('Invalid CSRF token.');
    }
}

function flash(string $msg, string $type = 'info'): void
{
    $_SESSION['flash'][] = ['msg' => $msg, 'type' => $type];
}

function get_flashes(): array
{
    $flashes = $_SESSION['flash'] ?? [];
    unset($_SESSION['flash']);
    return $flashes;
}

function enc_text(string $plain): string
{
    if ($plain === '') {
        return '';
    }
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $cipher = sodium_crypto_secretbox($plain, $nonce, $GLOBALS['KEY']);
    return base64_encode($nonce . $cipher);
}

function dec_text(?string $b64): string
{
    if ($b64 === null || $b64 === '') {
        return '';
    }

    $raw = base64_decode($b64, true);
    if ($raw === false || strlen($raw) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
        return '';
    }

    $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $cipher = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $plain = sodium_crypto_secretbox_open($cipher, $nonce, $GLOBALS['KEY']);

    return $plain === false ? '' : $plain;
}

function enc_blob(string $plain): string
{
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    return $nonce . sodium_crypto_secretbox($plain, $nonce, $GLOBALS['KEY']);
}

function dec_blob(?string $data): string
{
    if ($data === null || $data === '') {
        return '';
    }

    if (strlen($data) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
        return '';
    }

    $nonce = substr($data, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $cipher = substr($data, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $plain = sodium_crypto_secretbox_open($cipher, $nonce, $GLOBALS['KEY']);

    return $plain === false ? '' : $plain;
}

function city_key(string $city): string
{
    $city = trim($city);
    return function_exists('mb_strtolower') ? mb_strtolower($city, 'UTF-8') : strtolower($city);
}

function valid_username(string $username): bool
{
    return preg_match('/^[A-Za-z0-9_]{3,30}$/', $username) === 1;
}

function valid_password(string $password): bool
{
    return strlen($password) >= 8;
}

function dt(?int $ts): string
{
    return $ts ? date('Y-m-d H:i', $ts) : '-';
}

function is_online(array $user): bool
{
    return !empty($user['last_activity']) && (int)$user['last_activity'] >= time() - ONLINE_SECONDS;
}

function init_schema(PDO $pdo): void
{
    $pdo->exec('
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            pass_hash TEXT NOT NULL,
            city TEXT NOT NULL,
            city_key TEXT NOT NULL,
            bio_enc TEXT,
            avatar_mime TEXT,
            avatar_blob BLOB,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            last_login INTEGER,
            last_activity INTEGER
        );

        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            city_key TEXT NOT NULL UNIQUE,
            city_name TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            friend_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            status TEXT NOT NULL DEFAULT \'pending\',
            created_at INTEGER NOT NULL,
            UNIQUE(user_id, friend_id)
        );

        CREATE TABLE IF NOT EXISTS blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            blocker_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            blocked_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at INTEGER NOT NULL,
            UNIQUE(blocker_id, blocked_id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            recipient_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE,
            body_enc TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            deleted_by_sender INTEGER NOT NULL DEFAULT 0,
            deleted_by_recipient INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS room_presence (
            room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            last_seen INTEGER NOT NULL,
            UNIQUE(room_id, user_id)
        );

        CREATE INDEX IF NOT EXISTS idx_room_presence ON room_presence(room_id, last_seen);

        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_users_city ON users(city_key);
        CREATE INDEX IF NOT EXISTS idx_messages_direct ON messages(sender_id, recipient_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id, created_at);
    ');
}

function meta_get(PDO $pdo, string $key, ?string $default = null): ?string
{
    $st = $pdo->prepare('SELECT value FROM meta WHERE key = ?');
    $st->execute([$key]);
    $value = $st->fetchColumn();

    return $value === false ? $default : (string)$value;
}

function meta_set(PDO $pdo, string $key, string $value): void
{
    $pdo->prepare('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)')->execute([$key, $value]);
}

function get_or_create_room(PDO $pdo, string $cityName, string $cityKey): int
{
    $st = $pdo->prepare('SELECT id FROM rooms WHERE city_key = ?');
    $st->execute([$cityKey]);
    $id = $st->fetchColumn();

    if ($id !== false) {
        return (int)$id;
    }

    try {
        $pdo->prepare('INSERT INTO rooms (city_key, city_name, created_at) VALUES (?, ?, ?)')
            ->execute([$cityKey, $cityName, time()]);
        return (int)$pdo->lastInsertId();
    } catch (PDOException $exception) {
        $st->execute([$cityKey]);
        return (int)$st->fetchColumn();
    }
}

function maybe_bootstrap_admin(PDO $pdo): void
{
    $count = (int)$pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
    if ($count > 0) {
        return;
    }

    $username = getenv('DATING_ADMIN_USER');
    $password = getenv('DATING_ADMIN_PASS');
    $city = getenv('DATING_ADMIN_CITY') ?: 'Local';

    if (!$username || !$password) {
        return;
    }

    if (!valid_username($username) || !valid_password($password)) {
        return;
    }

    $cityKey = city_key($city);

    $pdo->prepare('
        INSERT INTO users (username, pass_hash, city, city_key, is_admin, created_at, last_login, last_activity)
        VALUES (?, ?, ?, ?, 1, ?, ?, ?)
    ')->execute([
        $username,
        password_hash($password, PASSWORD_DEFAULT),
        $city,
        $cityKey,
        time(),
        time(),
        time(),
    ]);

    get_or_create_room($pdo, $city, $cityKey);
}

function maybe_purge(PDO $pdo): void
{
    $last = (int)meta_get($pdo, 'last_purge', '0');
    if ($last > time() - 3600) {
        return;
    }

    meta_set($pdo, 'last_purge', (string)time());

    $messageCutoff = time() - (MESSAGE_TTL_DAYS * 86400);
    $pdo->prepare('DELETE FROM messages WHERE created_at < ?')->execute([$messageCutoff]);

    $userCutoff = time() - (int)(USER_TTL_YEARS * 365.25 * 86400);
    $pdo->prepare('DELETE FROM users WHERE COALESCE(last_login, created_at) < ?')->execute([$userCutoff]);
    room_cleanup($pdo);
}

function pdo(): PDO
{
    static $pdo = null;

    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $pdo = new PDO('sqlite:' . DB_FILE);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec('PRAGMA foreign_keys = ON');

    init_schema($pdo);
    maybe_bootstrap_admin($pdo);

    return $pdo;
}

function current_user(PDO $pdo): ?array
{
    if (empty($_SESSION['uid'])) {
        return null;
    }

    $st = $pdo->prepare('SELECT * FROM users WHERE id = ?');
    $st->execute([(int)$_SESSION['uid']]);
    $user = $st->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        unset($_SESSION['uid']);
        return null;
    }

    if (empty($user['last_activity']) || (int)$user['last_activity'] < time() - 60) {
        $now = time();
        $pdo->prepare('UPDATE users SET last_activity = ? WHERE id = ?')->execute([$now, (int)$user['id']]);
        $user['last_activity'] = $now;
    }

    return $user;
}

function find_user_by_id(PDO $pdo, int $id): ?array
{
    $st = $pdo->prepare('SELECT * FROM users WHERE id = ?');
    $st->execute([$id]);
    $user = $st->fetch(PDO::FETCH_ASSOC);

    return $user ?: null;
}

function find_user_by_username(PDO $pdo, string $username): ?array
{
    $st = $pdo->prepare('SELECT * FROM users WHERE username = ?');
    $st->execute([$username]);
    $user = $st->fetch(PDO::FETCH_ASSOC);

    return $user ?: null;
}

function is_blocked_between(PDO $pdo, int $a, int $b): bool
{
    if ($a === $b) {
        return false;
    }

    $st = $pdo->prepare('
        SELECT COUNT(*) FROM blocks
        WHERE (blocker_id = ? AND blocked_id = ?)
           OR (blocker_id = ? AND blocked_id = ?)
    ');
    $st->execute([$a, $b, $b, $a]);

    return (int)$st->fetchColumn() > 0;
}

function friendship_row(PDO $pdo, int $a, int $b): ?array
{
    if ($a === $b) {
        return null;
    }

    $st = $pdo->prepare('
        SELECT * FROM friendships
        WHERE (user_id = ? AND friend_id = ?)
           OR (user_id = ? AND friend_id = ?)
        LIMIT 1
    ');
    $st->execute([$a, $b, $b, $a]);
    $row = $st->fetch(PDO::FETCH_ASSOC);

    return $row ?: null;
}

function room_cleanup(PDO $pdo, int $thresholdSeconds = ROOM_PRESENCE_SECONDS): void
{
    $cutoff = time() - $thresholdSeconds;
    $pdo->prepare('DELETE FROM room_presence WHERE last_seen < ?')->execute([$cutoff]);
}

function room_signed_in(PDO $pdo, int $roomId, int $userId): bool
{
    $st = $pdo->prepare('SELECT COUNT(*) FROM room_presence WHERE room_id = ? AND user_id = ?');
    $st->execute([$roomId, $userId]);

    return (int)$st->fetchColumn() > 0;
}

function room_touch(PDO $pdo, int $roomId, int $userId): void
{
    $pdo->prepare('INSERT OR REPLACE INTO room_presence (room_id, user_id, last_seen) VALUES (?, ?, ?)')
        ->execute([$roomId, $userId, time()]);
}

function room_sign_out(PDO $pdo, int $roomId, int $userId): void
{
    $pdo->prepare('DELETE FROM room_presence WHERE room_id = ? AND user_id = ?')
        ->execute([$roomId, $userId]);
}

function room_users(PDO $pdo, int $roomId, int $thresholdSeconds = ROOM_PRESENCE_SECONDS): array
{
    $cutoff = time() - $thresholdSeconds;

    $st = $pdo->prepare('
        SELECT u.id, u.username, p.last_seen
        FROM room_presence p
        JOIN users u ON u.id = p.user_id
        WHERE p.room_id = ? AND p.last_seen >= ?
        ORDER BY u.username
    ');
    $st->execute([$roomId, $cutoff]);

    return $st->fetchAll(PDO::FETCH_ASSOC);
}

function render_header(string $title, ?array $me, int $refresh = 0): void
{
    echo '<!doctype html><html><head><meta charset="utf-8">';
    echo '<meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<title>' . e($title) . ' - ' . APP_NAME . '</title>';

    if ($refresh > 0) {
        echo '<meta http-equiv="refresh" content="' . (int)$refresh . '">';
    }

    echo '<style>
        body{font-family:system-ui,Arial,sans-serif;margin:1rem;line-height:1.4;}
        nav a{margin-right:.75rem;}
        table{border-collapse:collapse;}
        td,th{border:1px solid #ccc;padding:.3rem .5rem;}
        img.avatar{width:96px;height:96px;object-fit:cover;border-radius:8px;}
        .muted{color:#666;}
        .error{color:#a00;}
        .ok{color:#060;}
        .msg{margin:.3rem 0;padding:.4rem;border:1px solid #ddd;border-radius:6px;}
        .me{background:#eef;}
        form.inline{display:inline;}
        textarea,input[type=text],input[type=password]{width:100%;max-width:420px;padding:.35rem;}
    </style></head><body>';

    echo '<h1>' . APP_NAME . '</h1><nav>';

    if ($me) {
        echo '<a href="?action=home">Home</a>';
        echo '<a href="?action=cities">Cities</a>';
        echo '<a href="?action=messages">Messages</a>';
        echo '<a href="?action=friends">Friends</a>';
        echo '<a href="?action=blocks">Blocked</a>';
        echo '<a href="?action=user&id=' . (int)$me['id'] . '">Profile</a>';
        echo '<a href="?action=edit_profile">Edit Profile</a>';

        if (!empty($me['is_admin'])) {
            echo '<a href="?action=admin">Admin</a>';
        }

        echo '<form class="inline" method="post" action="?action=logout">' . csrf_field() .
            '<button>Logout (' . e($me['username']) . ')</button></form>';
    } else {
        echo '<a href="?action=login">Login</a>';
        echo '<a href="?action=register">Register</a>';
    }

    echo '</nav><hr>';

    foreach (get_flashes() as $flash) {
        echo '<div class="' . e($flash['type']) . '">' . e($flash['msg']) . '</div>';
    }
}

function render_footer(): void
{
    echo '</body></html>';
}

$pdo = pdo();

if (PHP_SAPI === 'cli') {
    $args = $_SERVER['argv'] ?? [];
    if (in_array('purge', $args, true)) {
        meta_set($pdo, 'last_purge', '0');
        maybe_purge($pdo);
        echo "Purge complete\n";
        exit;
    }

    exit("CLI usage: php index.php purge\n");
}

maybe_purge($pdo);
$me = current_user($pdo);
$action = $_REQUEST['action'] ?? 'home';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf();
}

if (!$me && !in_array($action, ['login', 'register'], true)) {
    redirect('?action=login');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    switch ($action) {
        case 'register':
            if ($me) {
                redirect('?action=home');
            }

            $username = trim($_POST['username'] ?? '');
            $password = $_POST['password'] ?? '';
            $city = trim($_POST['city'] ?? '');

            if (!valid_username($username)) {
                flash('Username must be 3-30 characters: letters, numbers, underscore.', 'error');
                redirect('?action=register');
            }

            if (!valid_password($password)) {
                flash('Password must be at least 8 characters.', 'error');
                redirect('?action=register');
            }

            if ($city === '') {
                flash('City is required.', 'error');
                redirect('?action=register');
            }

            $st = $pdo->prepare('SELECT COUNT(*) FROM users WHERE username = ?');
            $st->execute([$username]);
            if ((int)$st->fetchColumn() > 0) {
                flash('Username already exists.', 'error');
                redirect('?action=register');
            }

            $existingUsers = (int)$pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
            $isAdmin = $existingUsers === 0 ? 1 : 0;
            $key = city_key($city);

            $pdo->prepare('
                INSERT INTO users (username, pass_hash, city, city_key, is_admin, created_at, last_login, last_activity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ')->execute([
                $username,
                password_hash($password, PASSWORD_DEFAULT),
                $city,
                $key,
                $isAdmin,
                time(),
                time(),
                time(),
            ]);

            $uid = (int)$pdo->lastInsertId();
            get_or_create_room($pdo, $city, $key);

            session_regenerate_id(true);
            $_SESSION['uid'] = $uid;

            if ($isAdmin) {
                flash('First user created as admin.', 'ok');
            }

            redirect('?action=home');

        case 'login':
            if ($me) {
                redirect('?action=home');
            }

            $username = trim($_POST['username'] ?? '');
            $password = $_POST['password'] ?? '';

            $user = find_user_by_username($pdo, $username);

            if ($user && password_verify($password, $user['pass_hash'])) {
                session_regenerate_id(true);
                $_SESSION['uid'] = (int)$user['id'];

                $now = time();
                $pdo->prepare('UPDATE users SET last_login = ?, last_activity = ? WHERE id = ?')
                    ->execute([$now, $now, (int)$user['id']]);

                redirect('?action=home');
            }

            flash('Invalid username or password.', 'error');
            redirect('?action=login');

        case 'logout':
            if ($me) {
                $pdo->prepare('DELETE FROM room_presence WHERE user_id = ?')
                    ->execute([(int)$me['id']]);
            }

            $_SESSION = [];
            session_destroy();
            redirect('?action=login');

        case 'edit_profile':
            $city = trim($_POST['city'] ?? '');
            if ($city === '') {
                $city = $me['city'];
            }

            $bio = trim($_POST['bio'] ?? '');
            $cityKey = city_key($city);

            $pdo->prepare('UPDATE users SET city = ?, city_key = ?, bio_enc = ? WHERE id = ?')->execute([
                $city,
                $cityKey,
                $bio === '' ? null : enc_text($bio),
                (int)$me['id'],
            ]);

            get_or_create_room($pdo, $city, $cityKey);

            if (!empty($_FILES['avatar']['tmp_name']) && is_uploaded_file($_FILES['avatar']['tmp_name'])) {
                $error = $_FILES['avatar']['error'] ?? UPLOAD_ERR_NO_FILE;

                if ($error !== UPLOAD_ERR_OK) {
                    flash('Upload failed.', 'error');
                    redirect('?action=edit_profile');
                }

                if ($_FILES['avatar']['size'] > 2 * 1024 * 1024) {
                    flash('Image must be 2MB or smaller.', 'error');
                    redirect('?action=edit_profile');
                }

                $info = @getimagesize($_FILES['avatar']['tmp_name']);
                if (!$info) {
                    flash('Uploaded file is not an image.', 'error');
                    redirect('?action=edit_profile');
                }

                $mime = $info['mime'];
                $allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
                if (!in_array($mime, $allowed, true)) {
                    flash('Allowed image types: JPG, PNG, GIF, WEBP.', 'error');
                    redirect('?action=edit_profile');
                }

                $raw = file_get_contents($_FILES['avatar']['tmp_name']);
                if ($raw === false) {
                    flash('Could not read uploaded file.', 'error');
                    redirect('?action=edit_profile');
                }

                $blob = enc_blob($raw);
                $pdo->prepare('UPDATE users SET avatar_mime = ?, avatar_blob = ? WHERE id = ?')
                    ->execute([$mime, $blob, (int)$me['id']]);
            }

            flash('Profile saved.', 'ok');
            redirect('?action=edit_profile');

        case 'send_direct':
            $to = (int)($_POST['to'] ?? 0);
            $body = trim($_POST['body'] ?? '');

            $target = find_user_by_id($pdo, $to);
            if (!$target) {
                flash('User not found.', 'error');
                redirect('?action=messages');
            }

            if ($body === '') {
                redirect('?action=conv&with=' . $to);
            }

            if (is_blocked_between($pdo, (int)$me['id'], $to)) {
                flash('You cannot message this user.', 'error');
                redirect('?action=conv&with=' . $to);
            }

            $pdo->prepare('
                INSERT INTO messages (sender_id, recipient_id, room_id, body_enc, created_at)
                VALUES (?, ?, NULL, ?, ?)
            ')->execute([
                (int)$me['id'],
                $to,
                enc_text($body),
                time(),
            ]);

            redirect('?action=conv&with=' . $to);

        case 'send_room':
            $roomId = (int)($_POST['room_id'] ?? 0);
            $body = trim($_POST['body'] ?? '');

            $st = $pdo->prepare('SELECT * FROM rooms WHERE id = ?');
            $st->execute([$roomId]);
            $room = $st->fetch(PDO::FETCH_ASSOC);

            if (!$room) {
                flash('Room not found.', 'error');
                redirect('?action=cities');
            }

            if (!room_signed_in($pdo, $roomId, (int)$me['id'])) {
                flash('Sign in to the room before sending messages.', 'error');
                redirect('?action=room&id=' . $roomId);
            }

            if ($body === '') {
                redirect('?action=room&id=' . $roomId);
            }

            room_touch($pdo, $roomId, (int)$me['id']);

            $pdo->prepare('
                INSERT INTO messages (sender_id, recipient_id, room_id, body_enc, created_at)
                VALUES (?, NULL, ?, ?, ?)
            ')->execute([
                (int)$me['id'],
                $roomId,
                enc_text($body),
                time(),
            ]);

            redirect('?action=room&id=' . $roomId);

        case 'delete_msg':
            $messageId = (int)($_POST['message_id'] ?? 0);

            $st = $pdo->prepare('SELECT * FROM messages WHERE id = ?');
            $st->execute([$messageId]);
            $message = $st->fetch(PDO::FETCH_ASSOC);

            if (!$message) {
                flash('Message not found.', 'error');
                redirect('?action=messages');
            }

            if ($message['room_id'] !== null) {
                if ((int)$message['sender_id'] === (int)$me['id'] || (int)$me['is_admin'] === 1) {
                    $pdo->prepare('DELETE FROM messages WHERE id = ?')->execute([(int)$message['id']]);
                    flash('Message deleted.', 'ok');
                } else {
                    flash('Not allowed.', 'error');
                }

                redirect('?action=room&id=' . (int)$message['room_id']);
            }

            if ($message['recipient_id'] === null) {
                redirect('?action=messages');
            }

            $deletedBySender = (int)$message['deleted_by_sender'];
            $deletedByRecipient = (int)$message['deleted_by_recipient'];

            if ((int)$message['sender_id'] === (int)$me['id']) {
                $deletedBySender = 1;
            } elseif ((int)$message['recipient_id'] === (int)$me['id']) {
                $deletedByRecipient = 1;
            } else {
                flash('Not allowed.', 'error');
                redirect('?action=messages');
            }

            if ($deletedBySender && $deletedByRecipient) {
                $pdo->prepare('DELETE FROM messages WHERE id = ?')->execute([(int)$message['id']]);
            } else {
                $pdo->prepare('UPDATE messages SET deleted_by_sender = ?, deleted_by_recipient = ? WHERE id = ?')
                    ->execute([$deletedBySender, $deletedByRecipient, (int)$message['id']]);
            }

            $other = ((int)$message['sender_id'] === (int)$me['id'])
                ? (int)$message['recipient_id']
                : (int)$message['sender_id'];

            flash('Message removed.', 'ok');
            redirect('?action=conv&with=' . $other);
        case 'room_signin':
            $roomId = (int)($_POST['room_id'] ?? 0);

            $st = $pdo->prepare('SELECT id FROM rooms WHERE id = ?');
            $st->execute([$roomId]);

            if (!$st->fetchColumn()) {
                flash('Room not found.', 'error');
                redirect('?action=cities');
            }

            room_cleanup($pdo);
            room_touch($pdo, $roomId, (int)$me['id']);

            flash('Signed in to room. Others can now see you are here.', 'ok');
            redirect('?action=room&id=' . $roomId);

        case 'room_signout':
            $roomId = (int)($_POST['room_id'] ?? 0);

            room_sign_out($pdo, $roomId, (int)$me['id']);

            flash('Signed out of room.', 'ok');
            redirect('?action=room&id=' . $roomId);

        case 'room_heartbeat':
            $roomId = (int)($_POST['room_id'] ?? 0);

            $st = $pdo->prepare('SELECT id FROM rooms WHERE id = ?');
            $st->execute([$roomId]);

            header('Content-Type: application/json');

            if (!$st->fetchColumn()) {
                echo json_encode(['ok' => false, 'signed_in' => false]);
                exit;
            }

            room_cleanup($pdo);

            if (room_signed_in($pdo, $roomId, (int)$me['id'])) {
                room_touch($pdo, $roomId, (int)$me['id']);
                echo json_encode(['ok' => true, 'signed_in' => true]);
            } else {
                echo json_encode(['ok' => true, 'signed_in' => false]);
            }

            exit;

        case 'friend_add':
            $username = trim($_POST['username'] ?? '');
            $target = find_user_by_username($pdo, $username);

            if (!$target) {
                flash('User not found.', 'error');
                redirect('?action=friends');
            }

            $myId = (int)$me['id'];
            $targetId = (int)$target['id'];

            if ($myId === $targetId) {
                flash('You cannot add yourself.', 'error');
                redirect('?action=friends');
            }

            if (is_blocked_between($pdo, $myId, $targetId)) {
                flash('Cannot add this user.', 'error');
                redirect('?action=friends');
            }

            $row = friendship_row($pdo, $myId, $targetId);

            if ($row) {
                if ($row['status'] === 'accepted') {
                    flash('Already friends.', 'info');
                } elseif ((int)$row['user_id'] === $myId) {
                    flash('Friend request already sent.', 'info');
                } else {
                    $pdo->prepare('UPDATE friendships SET status = ? WHERE id = ?')
                        ->execute(['accepted', (int)$row['id']]);
                    flash('Friend request accepted.', 'ok');
                }
            } else {
                $pdo->prepare('INSERT INTO friendships (user_id, friend_id, status, created_at) VALUES (?, ?, ?, ?)')
                    ->execute([$myId, $targetId, 'pending', time()]);
                flash('Friend request sent.', 'ok');
            }

            redirect('?action=friends');

        case 'friend_accept':
            $id = (int)($_POST['id'] ?? 0);

            $st = $pdo->prepare('SELECT * FROM friendships WHERE id = ? AND friend_id = ? AND status = ?');
            $st->execute([$id, (int)$me['id'], 'pending']);
            $row = $st->fetch(PDO::FETCH_ASSOC);

            if ($row) {
                $pdo->prepare('UPDATE friendships SET status = ? WHERE id = ?')
                    ->execute(['accepted', (int)$row['id']]);
                flash('Friend added.', 'ok');
            }

            redirect('?action=friends');

        case 'friend_remove':
            $id = (int)($_POST['id'] ?? 0);

            $pdo->prepare('DELETE FROM friendships WHERE id = ? AND (user_id = ? OR friend_id = ?)')
                ->execute([$id, (int)$me['id'], (int)$me['id']]);

            flash('Friend removed.', 'ok');
            redirect('?action=friends');

        case 'block_user':
            $targetId = (int)($_POST['id'] ?? 0);

            if ($targetId === (int)$me['id']) {
                flash('You cannot block yourself.', 'error');
                redirect('?action=user&id=' . $targetId);
            }

            $pdo->prepare('INSERT OR IGNORE INTO blocks (blocker_id, blocked_id, created_at) VALUES (?, ?, ?)')
                ->execute([(int)$me['id'], $targetId, time()]);

            $pdo->prepare('
                DELETE FROM friendships
                WHERE (user_id = ? AND friend_id = ?)
                   OR (user_id = ? AND friend_id = ?)
            ')->execute([
                (int)$me['id'], $targetId,
                $targetId, (int)$me['id'],
            ]);

            flash('User blocked.', 'ok');
            redirect('?action=user&id=' . $targetId);

        case 'unblock_user':
            $targetId = (int)($_POST['id'] ?? 0);

            $pdo->prepare('DELETE FROM blocks WHERE blocker_id = ? AND blocked_id = ?')
                ->execute([(int)$me['id'], $targetId]);

            flash('User unblocked.', 'ok');
            redirect('?action=blocks');

        case 'admin_add_user':
            if ((int)$me['is_admin'] !== 1) {
                redirect('?action=home');
            }

            $username = trim($_POST['username'] ?? '');
            $password = $_POST['password'] ?? '';
            $city = trim($_POST['city'] ?? '');
            $isAdmin = !empty($_POST['is_admin']) ? 1 : 0;

            if (!valid_username($username) || !valid_password($password) || $city === '') {
                flash('Invalid user data. Username 3-30, password 8+, city required.', 'error');
                redirect('?action=admin');
            }

            $existing = find_user_by_username($pdo, $username);
            if ($existing) {
                flash('Username already exists.', 'error');
                redirect('?action=admin');
            }

            $cityKey = city_key($city);

            $pdo->prepare('
                INSERT INTO users (username, pass_hash, city, city_key, is_admin, created_at, last_login, last_activity)
                VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)
            ')->execute([
                $username,
                password_hash($password, PASSWORD_DEFAULT),
                $city,
                $cityKey,
                $isAdmin,
                time(),
            ]);

            get_or_create_room($pdo, $city, $cityKey);

            flash('User added.', 'ok');
            redirect('?action=admin');

        case 'admin_delete_user':
            if ((int)$me['is_admin'] !== 1) {
                redirect('?action=home');
            }

            $targetId = (int)($_POST['id'] ?? 0);
            $target = find_user_by_id($pdo, $targetId);

            if (!$target) {
                flash('User not found.', 'error');
                redirect('?action=admin');
            }

            if ($targetId === (int)$me['id']) {
                flash('You cannot delete yourself.', 'error');
                redirect('?action=admin');
            }

            if (!empty($target['is_admin'])) {
                $adminCount = (int)$pdo->query('SELECT COUNT(*) FROM users WHERE is_admin = 1')->fetchColumn();
                if ($adminCount <= 1) {
                    flash('Cannot delete the last admin.', 'error');
                    redirect('?action=admin');
                }
            }

            $pdo->prepare('DELETE FROM users WHERE id = ?')->execute([$targetId]);
            flash('User deleted.', 'ok');
            redirect('?action=admin');

        case 'admin_purge':
            if ((int)$me['is_admin'] !== 1) {
                redirect('?action=home');
            }

            meta_set($pdo, 'last_purge', '0');
            maybe_purge($pdo);

            flash('Manual purge completed.', 'ok');
            redirect('?action=admin');

        default:
            redirect('?action=home');
    }
}

switch ($action) {
    case 'login':
        if ($me) {
            redirect('?action=home');
        }

        $userCount = (int)$pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();

        render_header('Login', null);

        if ($userCount === 0) {
            echo '<p class="muted">No users yet. Register the first user as admin, or bootstrap with DATING_ADMIN_USER / DATING_ADMIN_PASS environment variables.</p>';
        }

        echo '<h2>Login</h2>
        <form method="post" action="?action=login">' . csrf_field() . '
            <p><input type="text" name="username" placeholder="Username" required></p>
            <p><input type="password" name="password" placeholder="Password" required></p>
            <p><button>Login</button></p>
        </form>
        <p><a href="?action=register">Register</a></p>';

        render_footer();
        break;

    case 'register':
        if ($me) {
            redirect('?action=home');
        }

        $userCount = (int)$pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();

        render_header('Register', null);

        if ($userCount === 0) {
            echo '<p class="muted">The first registered user becomes admin.</p>';
        }

        echo '<h2>Register</h2>
        <form method="post" action="?action=register">' . csrf_field() . '
            <p><input type="text" name="username" placeholder="Username" required></p>
            <p><input type="password" name="password" placeholder="Password" required></p>
            <p><input type="text" name="city" placeholder="City" required></p>
            <p><button>Create account</button></p>
        </form>
        <p><a href="?action=login">Login</a></p>';

        render_footer();
        break;

    case 'home':
        $roomId = get_or_create_room($pdo, $me['city'], $me['city_key']);

        $st = $pdo->prepare('SELECT COUNT(*) FROM users WHERE city_key = ?');
        $st->execute([$me['city_key']]);
        $cityUsers = (int)$st->fetchColumn();

        render_header('Home', $me);

        echo '<h2>Welcome, ' . e($me['username']) . '</h2>
        <p>Your city: <strong>' . e($me['city']) . '</strong></p>
        <p>Users in your city: ' . $cityUsers . '</p>
        <p><a href="?action=room&id=' . $roomId . '">Open your city chat room</a></p>
        <p><a href="?action=cities">Browse cities</a></p>
        <p><a href="?action=messages">Direct messages</a></p>
        <p><a href="?action=friends">Friends</a></p>';

        render_footer();
        break;

    case 'cities':
	$rows = $pdo->query('
    		SELECT city_key, MAX(city) AS city_name, COUNT(*) AS user_count
    		FROM users
    		GROUP BY city_key
    		ORDER BY user_count DESC
		')->fetchAll(PDO::FETCH_ASSOC);

        render_header('Cities', $me);

        echo '<h2>Cities</h2>';

        if (!$rows) {
            echo '<p>No cities yet.</p>';
        } else {
            echo '<table><tr><th>City</th><th>Users</th><th></th></tr>';
            foreach ($rows as $row) {
                echo '<tr>
                    <td>' . e($row['city_name']) . '</td>
                    <td>' . (int)$row['user_count'] . '</td>
                    <td><a href="?action=city&key=' . rawurlencode($row['city_key']) . '">View</a></td>
                </tr>';
            }
            echo '</table>';
        }

        render_footer();
        break;

    case 'city':
        $key = city_key($_GET['key'] ?? '');

        $st = $pdo->prepare('SELECT * FROM users WHERE city_key = ? ORDER BY username');
        $st->execute([$key]);
        $users = $st->fetchAll(PDO::FETCH_ASSOC);

        if (!$users) {
            render_header('City', $me);
            echo '<p>City not found.</p>';
            render_footer();
            break;
        }

        $cityName = $users[0]['city'];
        $roomId = get_or_create_room($pdo, $cityName, $key);

        render_header('City: ' . $cityName, $me);

        echo '<h2>' . e($cityName) . '</h2>
        <p><a href="?action=room&id=' . $roomId . '">Open city chat room</a></p>
        <table><tr><th>User</th><th>Status</th><th>Profile</th><th>Message</th></tr>';

        foreach ($users as $user) {
            $status = is_online($user) ? 'Online' : 'Offline';
            echo '<tr>
                <td>' . e($user['username']) . ((int)$user['id'] === (int)$me['id'] ? ' (you)' : '') . '</td>
                <td>' . $status . '</td>
                <td><a href="?action=user&id=' . (int)$user['id'] . '">Profile</a></td>
                <td><a href="?action=conv&with=' . (int)$user['id'] . '">Message</a></td>
            </tr>';
        }

        echo '</table>';

        render_footer();
        break;

    case 'room':
        $roomId = (int)($_GET['id'] ?? 0);

        $st = $pdo->prepare('SELECT * FROM rooms WHERE id = ?');
        $st->execute([$roomId]);
        $room = $st->fetch(PDO::FETCH_ASSOC);

        if (!$room) {
            render_header('Room', $me);
            echo '<p>Room not found.</p>';
            render_footer();
            break;
        }

        $myId = (int)$me['id'];

        room_cleanup($pdo);

        $signedIn = room_signed_in($pdo, $roomId, $myId);

        if ($signedIn) {
            room_touch($pdo, $roomId, $myId);
        }

        $presentUsers = room_users($pdo, $roomId);

        $st = $pdo->prepare('
            SELECT m.id, m.sender_id, m.body_enc, m.created_at, u.username
            FROM messages m
            JOIN users u ON u.id = m.sender_id
            WHERE m.room_id = ?
              AND m.deleted_by_sender = 0
              AND m.sender_id NOT IN (SELECT blocked_id FROM blocks WHERE blocker_id = ?)
              AND m.sender_id NOT IN (SELECT blocker_id FROM blocks WHERE blocked_id = ?)
            ORDER BY m.id DESC
            LIMIT 100
        ');
        $st->execute([$roomId, $myId, $myId]);
        $messages = array_reverse($st->fetchAll(PDO::FETCH_ASSOC));

        render_header('Room: ' . $room['city_name'], $me);

        echo '<h2>Chat room: ' . e($room['city_name']) . '</h2>';
        echo '<p><a href="?action=cities">Back to cities</a></p>';

        echo '<div style="border:1px solid #ccc;padding:.5rem;margin:.5rem 0;">';

        if ($signedIn) {
            echo '<strong>You are signed in to this room.</strong> ';
            echo '<form class="inline" method="post" action="?action=room_signout">' . csrf_field() .
                '<input type="hidden" name="room_id" value="' . $roomId . '">' .
                '<button>Sign out of room</button></form>';
        } else {
            echo '<strong>You are not signed in to this room.</strong> ';
            echo '<form class="inline" method="post" action="?action=room_signin">' . csrf_field() .
                '<input type="hidden" name="room_id" value="' . $roomId . '">' .
                '<button>Sign in to room</button></form>';
        }

        echo '<hr><strong>Here now:</strong> ';

        if (!$presentUsers) {
            echo '<span class="muted">No one is signed in.</span>';
        } else {
            $names = [];
            foreach ($presentUsers as $presentUser) {
                $names[] = e($presentUser['username']) . ((int)$presentUser['id'] === $myId ? ' (you)' : '');
            }
            echo implode(', ', $names);
        }

        echo '</div>';

        foreach ($messages as $message) {
            $mine = (int)$message['sender_id'] === $myId;
            $class = $mine ? 'msg me' : 'msg';
            $body = e(dec_text($message['body_enc']));

            echo '<div class="' . $class . '">';
            echo '<strong>' . e($message['username']) . '</strong> ';
            echo '<span class="muted">' . dt((int)$message['created_at']) . '</span><br>';
            echo nl2br($body);

            if ($mine || (int)$me['is_admin'] === 1) {
                echo '<form class="inline" method="post" action="?action=delete_msg">' . csrf_field() .
                    '<input type="hidden" name="message_id" value="' . (int)$message['id'] . '">' .
                    '<button onclick="return confirm(\'Delete this message?\')">Delete</button></form>';
            }

            echo '</div>';
        }

        echo '<hr>';

        if ($signedIn) {
            echo '
            <form method="post" action="?action=send_room">' . csrf_field() . '
                <input type="hidden" name="room_id" value="' . $roomId . '">
                <p><textarea id="msgbox" name="body" rows="3" required></textarea></p>
                <p><button>Send to room</button></p>
            </form>';
        } else {
            echo '<p class="muted">Sign in to the room to send messages.</p>';
        }

        echo '<script>
            var roomId = ' . $roomId . ';
            var csrf = ' . json_encode(csrf_token()) . ';
            var signedIn = ' . ($signedIn ? 'true' : 'false') . ';

            setTimeout(function () {
                var el = document.getElementById("msgbox");
                if (!el || el.value.trim() === "") {
                    location.reload();
                }
            }, 5000);

            if (signedIn) {
                setInterval(function () {
                    fetch("?action=room_heartbeat", {
                        method: "POST",
                        headers: {"Content-Type": "application/x-www-form-urlencoded"},
                        body: "csrf=" + encodeURIComponent(csrf) + "&room_id=" + encodeURIComponent(roomId)
                    }).catch(function(){});
                }, 30000);
            }
        </script>';

        render_footer();
        break;

    case 'messages':
        $myId = (int)$me['id'];

        $st = $pdo->prepare('
            SELECT m.id, m.sender_id, m.recipient_id, m.created_at,
                   u.id AS other_id, u.username
            FROM messages m
            JOIN users u ON u.id = CASE WHEN m.sender_id = ? THEN m.recipient_id ELSE m.sender_id END
            WHERE m.room_id IS NULL
              AND (
                    (m.sender_id = ? AND m.deleted_by_sender = 0)
                 OR (m.recipient_id = ? AND m.deleted_by_recipient = 0)
              )
            ORDER BY m.created_at DESC
        ');
        $st->execute([$myId, $myId, $myId]);
        $rows = $st->fetchAll(PDO::FETCH_ASSOC);

        $conversations = [];
        foreach ($rows as $row) {
            $otherId = (int)$row['other_id'];
            if (!isset($conversations[$otherId])) {
                $conversations[$otherId] = [
                    'username' => $row['username'],
                    'last' => (int)$row['created_at'],
                    'count' => 1,
                ];
            } else {
                $conversations[$otherId]['count']++;
            }
        }

        render_header('Messages', $me);

        echo '<h2>Direct messages</h2>';

        if (!$conversations) {
            echo '<p>No direct messages yet.</p>';
        } else {
            echo '<table><tr><th>User</th><th>Last activity</th><th>Visible messages</th><th></th></tr>';
            foreach ($conversations as $otherId => $conversation) {
                echo '<tr>
                    <td>' . e($conversation['username']) . '</td>
                    <td>' . dt($conversation['last']) . '</td>
                    <td>' . (int)$conversation['count'] . '</td>
                    <td><a href="?action=conv&with=' . $otherId . '">Open</a></td>
                </tr>';
            }
            echo '</table>';
        }

        render_footer();
        break;

    case 'conv':
        $otherId = (int)($_GET['with'] ?? 0);
        $other = find_user_by_id($pdo, $otherId);

        if (!$other) {
            render_header('Conversation', $me);
            echo '<p>User not found.</p>';
            render_footer();
            break;
        }

        if ($otherId === (int)$me['id']) {
            redirect('?action=messages');
        }

        $myId = (int)$me['id'];

        $st = $pdo->prepare('
            SELECT * FROM messages
            WHERE room_id IS NULL
              AND (
                    (sender_id = ? AND recipient_id = ? AND deleted_by_sender = 0)
                 OR (sender_id = ? AND recipient_id = ? AND deleted_by_recipient = 0)
              )
            ORDER BY id ASC
        ');
        $st->execute([$myId, $otherId, $otherId, $myId]);
        $messages = $st->fetchAll(PDO::FETCH_ASSOC);

        $iBlockedThem = (int)$pdo->prepare('SELECT COUNT(*) FROM blocks WHERE blocker_id = ? AND blocked_id = ?')
            ->execute([$myId, $otherId]) ? (int)$pdo->query('SELECT COUNT(*) FROM blocks WHERE blocker_id = ' . $pdo->quote((string)$myId) . ' AND blocked_id = ' . $pdo->quote((string)$otherId))->fetchColumn() : 0;

        $theyBlockedMe = (int)$pdo->query('SELECT COUNT(*) FROM blocks WHERE blocker_id = ' . $pdo->quote((string)$otherId) . ' AND blocked_id = ' . $pdo->quote((string)$myId))->fetchColumn();

        $blocked = $iBlockedThem > 0 || $theyBlockedMe > 0;

        render_header('Chat with ' . $other['username'], $me);

        echo '<h2>Chat with ' . e($other['username']) . '</h2>
        <p>
            <a href="?action=messages">Back</a> |
            <a href="?action=user&id=' . $otherId . '">Profile</a>
        </p>';

        if ($theyBlockedMe) {
            echo '<p class="error">This user has blocked you.</p>';
        }

        if ($iBlockedThem) {
            echo '<p class="error">You have blocked this user.</p>
            <form method="post" action="?action=unblock_user">' . csrf_field() . '
                <input type="hidden" name="id" value="' . $otherId . '">
                <button>Unblock</button>
            </form>';
        }

        foreach ($messages as $message) {
            $mine = (int)$message['sender_id'] === $myId;
            $class = $mine ? 'msg me' : 'msg';
            $body = e(dec_text($message['body_enc']));

            echo '<div class="' . $class . '">';
            echo '<span class="muted">' . dt((int)$message['created_at']) . '</span><br>';
            echo nl2br($body);
            echo '<form class="inline" method="post" action="?action=delete_msg">' . csrf_field() .
                '<input type="hidden" name="message_id" value="' . (int)$message['id'] . '">' .
                '<button onclick="return confirm(\'Remove this message?\')">Remove</button></form>';
            echo '</div>';
        }

        if (!$blocked) {
            echo '<hr>
            <form method="post" action="?action=send_direct">' . csrf_field() . '
                <input type="hidden" name="to" value="' . $otherId . '">
                <p><textarea id="msgbox" name="body" rows="3" required></textarea></p>
                <p><button>Send</button></p>
            </form>
            <script>
                setTimeout(function () {
                    var el = document.getElementById("msgbox");
                    if (!el || el.value.trim() === "") {
                        location.reload();
                    }
                }, 5000);
            </script>';
        }

        render_footer();
        break;

        case 'admin_change_my_password':
            if ((int)$me['is_admin'] !== 1) {
                redirect('?action=home');
            }

            $old = $_POST['old_password'] ?? '';
            $new = $_POST['new_password'] ?? '';
            $confirm = $_POST['confirm_password'] ?? '';

            $current = find_user_by_id($pdo, (int)$me['id']);

            if (!$current || !password_verify($old, $current['pass_hash'])) {
                flash('Current password is incorrect.', 'error');
                redirect('?action=admin');
            }

            if (!valid_password($new)) {
                flash('New password must be at least 8 characters.', 'error');
                redirect('?action=admin');
            }

            if ($new !== $confirm) {
                flash('New passwords do not match.', 'error');
                redirect('?action=admin');
            }

            $pdo->prepare('UPDATE users SET pass_hash = ? WHERE id = ?')->execute([
                password_hash($new, PASSWORD_DEFAULT),
                (int)$me['id'],
            ]);

            flash('Your password has been changed.', 'ok');
            redirect('?action=admin');

        case 'admin_change_user_password':
            if ((int)$me['is_admin'] !== 1) {
                redirect('?action=home');
            }

            $userId = (int)($_POST['user_id'] ?? 0);
            $new = $_POST['new_password'] ?? '';
            $confirm = $_POST['confirm_password'] ?? '';

            if ($userId === (int)$me['id']) {
                flash('Use "Change my password" for your own account.', 'error');
                redirect('?action=admin');
            }

            $target = find_user_by_id($pdo, $userId);

            if (!$target) {
                flash('User not found.', 'error');
                redirect('?action=admin');
            }

            if (!valid_password($new)) {
                flash('New password must be at least 8 characters.', 'error');
                redirect('?action=admin');
            }

            if ($new !== $confirm) {
                flash('New passwords do not match.', 'error');
                redirect('?action=admin');
            }

            $pdo->prepare('UPDATE users SET pass_hash = ? WHERE id = ?')->execute([
                password_hash($new, PASSWORD_DEFAULT),
                $userId,
            ]);

            flash('Password updated for ' . $target['username'] . '.', 'ok');
            redirect('?action=admin');

    case 'friends':
        $myId = (int)$me['id'];

        $st = $pdo->prepare('
            SELECT f.id AS friendship_id, u.*
            FROM friendships f
            JOIN users u ON u.id = CASE WHEN f.user_id = ? THEN f.friend_id ELSE f.user_id END
            WHERE f.status = ? AND (f.user_id = ? OR f.friend_id = ?)
            ORDER BY u.username
        ');
        $st->execute([$myId, 'accepted', $myId, $myId]);
        $friends = $st->fetchAll(PDO::FETCH_ASSOC);

        $st = $pdo->prepare('
            SELECT f.id, u.username
            FROM friendships f
            JOIN users u ON u.id = f.user_id
            WHERE f.friend_id = ? AND f.status = ?
        ');
        $st->execute([$myId, 'pending']);
        $incoming = $st->fetchAll(PDO::FETCH_ASSOC);

        $st = $pdo->prepare('
            SELECT f.id, u.username
            FROM friendships f
            JOIN users u ON u.id = f.friend_id
            WHERE f.user_id = ? AND f.status = ?
        ');
        $st->execute([$myId, 'pending']);
        $outgoing = $st->fetchAll(PDO::FETCH_ASSOC);

        render_header('Friends', $me);

        echo '<h2>Friends</h2>';

        echo '<h3>Add friend</h3>
        <form method="post" action="?action=friend_add">' . csrf_field() . '
            <p><input type="text" name="username" placeholder="Username" required></p>
            <p><button>Add</button></p>
        </form>';

        if ($incoming) {
            echo '<h3>Incoming requests</h3><ul>';
            foreach ($incoming as $request) {
                echo '<li>' . e($request['username']) . '
                    <form class="inline" method="post" action="?action=friend_accept">' . csrf_field() .
                    '<input type="hidden" name="id" value="' . (int)$request['id'] . '">
                    <button>Accept</button></form>
                </li>';
            }
            echo '</ul>';
        }

        if ($outgoing) {
            echo '<h3>Sent requests</h3><ul>';
            foreach ($outgoing as $request) {
                echo '<li>' . e($request['username']) . ' <span class="muted">pending</span></li>';
            }
            echo '</ul>';
        }

        echo '<h3>Friend list</h3>';

        if (!$friends) {
            echo '<p>No friends yet.</p>';
        } else {
            echo '<table><tr><th>Friend</th><th>Status</th><th>Profile</th><th>Message</th><th></th></tr>';
            foreach ($friends as $friend) {
                $status = is_online($friend) ? 'Online' : 'Offline';
                echo '<tr>
                    <td>' . e($friend['username']) . '</td>
                    <td>' . $status . '</td>
                    <td><a href="?action=user&id=' . (int)$friend['id'] . '">Profile</a></td>
                    <td><a href="?action=conv&with=' . (int)$friend['id'] . '">Message</a></td>
                    <td>
                        <form class="inline" method="post" action="?action=friend_remove">' . csrf_field() . '
                            <input type="hidden" name="id" value="' . (int)$friend['friendship_id'] . '">
                            <button onclick="return confirm(\'Remove friend?\')">Remove</button>
                        </form>
                    </td>
                </tr>';
            }
            echo '</table>';
        }

        render_footer();
        break;

    case 'blocks':
        $myId = (int)$me['id'];

        $st = $pdo->prepare('
            SELECT b.id, u.id AS blocked_id, u.username
            FROM blocks b
            JOIN users u ON u.id = b.blocked_id
            WHERE b.blocker_id = ?
            ORDER BY u.username
        ');
        $st->execute([$myId]);
        $blocked = $st->fetchAll(PDO::FETCH_ASSOC);

        render_header('Blocked users', $me);

        echo '<h2>Blocked users</h2>';

        if (!$blocked) {
            echo '<p>No blocked users.</p>';
        } else {
            echo '<table><tr><th>User</th><th></th></tr>';
            foreach ($blocked as $block) {
                echo '<tr>
                    <td>' . e($block['username']) . '</td>
                    <td>
                        <form class="inline" method="post" action="?action=unblock_user">' . csrf_field() . '
                            <input type="hidden" name="id" value="' . (int)$block['blocked_id'] . '">
                            <button>Unblock</button>
                        </form>
                    </td>
                </tr>';
            }
            echo '</table>';
        }

        render_footer();
        break;

    case 'user':
        $userId = (int)($_GET['id'] ?? 0);
        $user = find_user_by_id($pdo, $userId);

        if (!$user) {
            render_header('Profile', $me);
            echo '<p>User not found.</p>';
            render_footer();
            break;
        }

        $myId = (int)$me['id'];
        $isMe = $userId === $myId;

        $bio = dec_text($user['bio_enc']);

        render_header('Profile: ' . $user['username'], $me);

        echo '<h2>' . e($user['username']) . '</h2>';

        if (!empty($user['avatar_blob']) && !empty($user['avatar_mime'])) {
            echo '<p><img class="avatar" alt="Avatar" src="?action=avatar&id=' . (int)$user['id'] . '"></p>';
        }

        echo '<p>City: ' . e($user['city']) . '</p>';
        echo '<p>Status: ' . (is_online($user) ? 'Online' : 'Offline') . '</p>';

        if ($bio !== '') {
            echo '<p>About:<br>' . nl2br(e($bio)) . '</p>';
        }

        if ($isMe) {
            echo '<p><a href="?action=edit_profile">Edit profile</a></p>';
        } else {
            $iBlockedThem = (int)$pdo->query('
                SELECT COUNT(*) FROM blocks
                WHERE blocker_id = ' . $pdo->quote((string)$myId) . '
                  AND blocked_id = ' . $pdo->quote((string)$userId) . '
            ')->fetchColumn();

            $theyBlockedMe = (int)$pdo->query('
                SELECT COUNT(*) FROM blocks
                WHERE blocker_id = ' . $pdo->quote((string)$userId) . '
                  AND blocked_id = ' . $pdo->quote((string)$myId) . '
            ')->fetchColumn();

            if ($theyBlockedMe) {
                echo '<p class="error">This user has blocked you.</p>';
            } elseif ($iBlockedThem) {
                echo '<p class="error">You have blocked this user.</p>
                <form method="post" action="?action=unblock_user">' . csrf_field() . '
                    <input type="hidden" name="id" value="' . $userId . '">
                    <button>Unblock</button>
                </form>';
            } else {
                echo '<p><a href="?action=conv&with=' . $userId . '">Message</a></p>';

                $friendship = friendship_row($pdo, $myId, $userId);

                if ($friendship) {
                    if ($friendship['status'] === 'accepted') {
                        echo '<form method="post" action="?action=friend_remove">' . csrf_field() . '
                            <input type="hidden" name="id" value="' . (int)$friendship['id'] . '">
                            <button>Remove friend</button>
                        </form>';
                    } elseif ((int)$friendship['user_id'] === $myId) {
                        echo '<p class="muted">Friend request sent.</p>';
                    } else {
                        echo '<form method="post" action="?action=friend_accept">' . csrf_field() . '
                            <input type="hidden" name="id" value="' . (int)$friendship['id'] . '">
                            <button>Accept friend request</button>
                        </form>';
                    }
                } else {
                    echo '<form method="post" action="?action=friend_add">' . csrf_field() . '
                        <input type="hidden" name="username" value="' . e($user['username']) . '">
                        <button>Add friend</button>
                    </form>';
                }

                echo '<form method="post" action="?action=block_user">' . csrf_field() . '
                    <input type="hidden" name="id" value="' . $userId . '">
                    <button onclick="return confirm(\'Block this user?\')">Block</button>
                </form>';
            }
        }

        render_footer();
        break;

    case 'edit_profile':
        $bio = dec_text($me['bio_enc']);

        render_header('Edit profile', $me);

        echo '<h2>Edit profile</h2>
        <form method="post" action="?action=edit_profile" enctype="multipart/form-data">' . csrf_field() . '
            <p>Username: <strong>' . e($me['username']) . '</strong></p>
            <p><input type="text" name="city" value="' . e($me['city']) . '" placeholder="City"></p>
            <p><textarea name="bio" rows="5" placeholder="About you">' . e($bio) . '</textarea></p>
            <p><input type="file" name="avatar" accept="image/jpeg,image/png,image/gif,image/webp"></p>
            <p><button>Save</button></p>
        </form>';

        render_footer();
        break;

    case 'avatar':
        $userId = (int)($_GET['id'] ?? 0);
        $user = find_user_by_id($pdo, $userId);

        if (!$user || empty($user['avatar_blob']) || empty($user['avatar_mime'])) {
            http_response_code(404);
            exit;
        }

        $data = dec_blob($user['avatar_blob']);
        if ($data === '') {
            http_response_code(404);
            exit;
        }

        header('Content-Type: ' . $user['avatar_mime']);
        header('Content-Length: ' . strlen($data));
        header('Cache-Control: private, max-age=3600');
        echo $data;
        exit;

    case 'admin':
        if ((int)$me['is_admin'] !== 1) {
            redirect('?action=home');
        }

        $users = $pdo->query('SELECT * FROM users ORDER BY username')->fetchAll(PDO::FETCH_ASSOC);
        $adminCount = (int)$pdo->query('SELECT COUNT(*) FROM users WHERE is_admin = 1')->fetchColumn();

        $otherUsers = [];
        foreach ($users as $user) {
            if ((int)$user['id'] !== (int)$me['id']) {
                $otherUsers[] = $user;
            }
        }

        render_header('Admin', $me);

        echo '<h2>Admin console</h2>';

        echo '<form method="post" action="?action=admin_purge">' . csrf_field() . '
            <button onclick="return confirm(\'Run purge now?\')">Run purge now</button>
        </form>';

        echo '<h3>Add user</h3>
        <form method="post" action="?action=admin_add_user">' . csrf_field() . '
            <p><input type="text" name="username" placeholder="Username" required></p>
            <p><input type="password" name="password" placeholder="Password" required></p>
            <p><input type="text" name="city" placeholder="City" required></p>
            <p><label><input type="checkbox" name="is_admin" value="1"> Admin</label></p>
            <p><button>Add user</button></p>
        </form>';

        echo '<h3>Change my password</h3>
        <form method="post" action="?action=admin_change_my_password">' . csrf_field() . '
            <p><input type="password" name="old_password" placeholder="Current password" required></p>
            <p><input type="password" name="new_password" placeholder="New password" required></p>
            <p><input type="password" name="confirm_password" placeholder="Confirm new password" required></p>
            <p><button>Change my password</button></p>
        </form>';

        if ($otherUsers) {
            echo '<h3>Reset another user password</h3>
            <form method="post" action="?action=admin_change_user_password">' . csrf_field() . '
                <p>
                    <select name="user_id" required>';

            foreach ($otherUsers as $otherUser) {
                echo '<option value="' . (int)$otherUser['id'] . '">' . e($otherUser['username']) . '</option>';
            }

            echo '</select>
                </p>
                <p><input type="password" name="new_password" placeholder="New password" required></p>
                <p><input type="password" name="confirm_password" placeholder="Confirm new password" required></p>
                <p><button>Reset user password</button></p>
            </form>';
        } else {
            echo '<h3>Reset another user password</h3>
            <p class="muted">No other users exist.</p>';
        }

        echo '<h3>Users</h3>
        <table>
            <tr>
                <th>ID</th>
                <th>Username</th>
                <th>City</th>
                <th>Admin</th>
                <th>Last login</th>
                <th>Last activity</th>
                <th>Delete</th>
            </tr>';

        foreach ($users as $user) {
            $canDelete = ((int)$user['id'] !== (int)$me['id']);

            if ($canDelete && !empty($user['is_admin']) && $adminCount <= 1) {
                $canDelete = false;
            }

            echo '<tr>
                <td>' . (int)$user['id'] . '</td>
                <td>' . e($user['username']) . '</td>
                <td>' . e($user['city']) . '</td>
                <td>' . (!empty($user['is_admin']) ? 'Yes' : 'No') . '</td>
                <td>' . dt(!empty($user['last_login']) ? (int)$user['last_login'] : null) . '</td>
                <td>' . dt(!empty($user['last_activity']) ? (int)$user['last_activity'] : null) . '</td>
                <td>';

            if ($canDelete) {
                echo '<form class="inline" method="post" action="?action=admin_delete_user">' . csrf_field() . '
                    <input type="hidden" name="id" value="' . (int)$user['id'] . '">
                    <button onclick="return confirm(\'Delete this user?\')">Delete</button>
                </form>';
            } else {
                echo '<span class="muted">Protected</span>';
            }

            echo '</td></tr>';
        }

        echo '</table>';

        render_footer();
        break;

    default:
        redirect('?action=home');
}