<?php
// File: api_lavender.php
// Standalone JSON API for jocarsa-lavender (read-only)
// POST JSON: { "username":"...", "password":"...", "form_hash":"...", "key":"Campo X", "value":"..." }
// Optional: "case_insensitive": true, "strict": false
// Response: application/json

header('Content-Type: application/json; charset=utf-8');

// -------- Helpers ----------
function respond($arr, $code = 200) {
    http_response_code($code);
    echo json_encode($arr, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
function get_input() {
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        // Fallback to form-encoded
        $data = $_POST;
    }
    return $data ?: [];
}
function open_db() {
    // Primary path used by the app
    $candidates = [
        __DIR__ . '/../databases/lavender.sqlite', // same as index.php uses
        __DIR__ . '/lavender.sqlite',
        __DIR__ . '/db.sqlite'
    ];
    foreach ($candidates as $p) {
        if (is_readable($p)) {
            $db = new SQLite3($p);
            // Enable foreign keys & WAL read-safety if available
            @$db->exec('PRAGMA foreign_keys = ON;');
            return $db;
        }
    }
    respond(["ok"=>false,"error"=>"Database not found/readable"], 500);
}

// -------- Input ----------
$in = get_input();
$username = isset($in['username']) ? trim($in['username']) : '';
$password = isset($in['password']) ? trim($in['password']) : '';
$form_hash = isset($in['form_hash']) ? trim($in['form_hash']) : '';
$key   = isset($in['key']) ? trim($in['key']) : '';
$value = isset($in['value']) ? $in['value'] : '';

$case_insensitive = isset($in['case_insensitive']) ? (bool)$in['case_insensitive'] : false;
$strict_compare   = isset($in['strict']) ? (bool)$in['strict'] : true;

if ($username === '' || $password === '' || $form_hash === '' || $key === '') {
    respond([
        "ok"=>false,
        "error"=>"Missing required fields. Required: username, password, form_hash, key. Optional: value (can be empty string), case_insensitive, strict."
    ], 400);
}

// -------- Open DB (read-only logic; no writes) ----------
$db = open_db();

// -------- Auth ----------
$stmt = $db->prepare("SELECT username FROM users WHERE username=:u AND password=:p");
$stmt->bindValue(':u', $username, SQLITE3_TEXT);
$stmt->bindValue(':p', $password, SQLITE3_TEXT);
$auth = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
if (!$auth) {
    respond(["ok"=>false,"error"=>"Invalid credentials"], 401);
}

// -------- Resolve form by hash & check ownership --------
$stmt = $db->prepare("SELECT f.id, f.title, f.hash
                      FROM forms f
                      LEFT JOIN form_owners fo ON fo.form_id = f.id
                      WHERE f.hash = :h");
$stmt->bindValue(':h', $form_hash, SQLITE3_TEXT);
$form = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
if (!$form) {
    respond(["ok"=>false,"error"=>"Form not found for provided hash"], 404);
}

// If there is an owner registered, require match; if not, allow (for backward compat)
$ownerStmt = $db->prepare("SELECT username FROM form_owners WHERE form_id = :fid");
$ownerStmt->bindValue(':fid', $form['id'], SQLITE3_INTEGER);
$owner = $ownerStmt->execute()->fetchArray(SQLITE3_ASSOC);
if ($owner && $owner['username'] !== $username) {
    respond(["ok"=>false,"error"=>"You don't have access to this form"], 403);
}

// -------- Load submissions for this form (read-only) --------
$subs = [];
$q = $db->prepare("SELECT id, form_id, unique_id, data, datetime, epoch, ip, user_agent, created_at
                   FROM submissions
                   WHERE form_id = :fid
                   ORDER BY id DESC");
$q->bindValue(':fid', $form['id'], SQLITE3_INTEGER);
$r = $q->execute();

while ($row = $r->fetchArray(SQLITE3_ASSOC)) {
    $payload = json_decode($row['data'], true);
    if (!is_array($payload)) $payload = [];

    // Matching logic on key/value
    if (!array_key_exists($key, $payload)) {
        continue;
    }
    $candidate = $payload[$key];

    $match = false;
    if ($strict_compare) {
        if ($case_insensitive && is_string($candidate) && is_string($value)) {
            $match = (mb_strtolower($candidate) === mb_strtolower($value));
        } else {
            $match = ($candidate === $value);
        }
    } else {
        // non-strict: substring/loose match when strings; fallback to == otherwise
        if (is_string($candidate) && is_string($value)) {
            $match = $case_insensitive
                ? mb_stripos($candidate, $value) !== false
                : mb_strpos($candidate, $value) !== false;
        } else {
            $match = ($candidate == $value);
        }
    }

    if ($match) {
        $subs[] = [
            "id"         => (int)$row['id'],
            "unique_id"  => $row['unique_id'],
            "datetime"   => $row['datetime'],
            "epoch"      => (int)$row['epoch'],
            "ip"         => $row['ip'],
            "user_agent" => $row['user_agent'],
            "created_at" => $row['created_at'],
            "data"       => $payload        // full row data (form fields)
        ];
    }
}

// -------- Also return form columns (field titles) for convenience --------
$cols = [];
$cs = $db->prepare("SELECT field_title FROM controls WHERE form_id = :fid ORDER BY id ASC");
$cs->bindValue(':fid', $form['id'], SQLITE3_INTEGER);
$cr = $cs->execute();
while ($c = $cr->fetchArray(SQLITE3_ASSOC)) {
    $cols[] = $c['field_title'];
}

// -------- Response --------
respond([
    "ok"        => true,
    "form"      => ["id" => (int)$form['id'], "title" => $form['title'], "hash" => $form['hash']],
    "query"     => ["key"=>$key, "value"=>$value, "strict"=>$strict_compare, "case_insensitive"=>$case_insensitive],
    "columns"   => $cols,
    "matches"   => $subs,
    "count"     => count($subs)
]);

