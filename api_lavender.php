<?php
// File: api_lavender_v2.php
// Read-only JSON API for jocarsa-lavender (improved matching & row shape)
// POST JSON:
// {
//   "username":"...","password":"...","form_hash":"...",
//   "key":"Indica tu DNI","value":"Z3493109N",
//   "mode":"equals|icontains|istartswith|iendswith", // optional (default equals)
//   "single": false                                   // optional (default false)
// }
//
// Response: application/json

header('Content-Type: application/json; charset=utf-8');

// ---------- Utils ----------
function respond($arr, $code = 200) {
    http_response_code($code);
    echo json_encode($arr, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
function get_input() {
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    if (!is_array($data)) $data = $_POST;
    return $data ?: [];
}
function open_db() {
    $candidates = [
        __DIR__ . '/../databases/lavender.sqlite',
        __DIR__ . '/lavender.sqlite',
        __DIR__ . '/db.sqlite'
    ];
    foreach ($candidates as $p) {
        if (is_readable($p)) {
            $db = new SQLite3($p);
            @$db->exec('PRAGMA foreign_keys = ON;');
            return $db;
        }
    }
    respond(["ok"=>false,"error"=>"Database not found/readable"], 500);
}
function strip_accents($s) {
    $s = iconv('UTF-8','ASCII//TRANSLIT//IGNORE',$s);
    return $s === false ? '' : $s;
}
function norm($v) {
    if ($v === null) return '';
    if (!is_string($v)) $v = strval($v);
    $v = trim($v);
    $v = mb_strtolower($v, 'UTF-8');
    $v = strip_accents($v);
    // colapsar espacios múltiple
    $v = preg_replace('/\s+/u',' ', $v);
    return $v;
}
function similar_enough($a, $b) {
    // devuelve true si similares >= 90%
    similar_text($a, $b, $pct);
    return $pct >= 90.0;
}

// ---------- Input ----------
$in = get_input();
$username = isset($in['username']) ? trim($in['username']) : '';
$password = isset($in['password']) ? trim($in['password']) : '';
$form_hash = isset($in['form_hash']) ? trim($in['form_hash']) : '';
$keyReq    = isset($in['key']) ? trim($in['key']) : '';
$valueReq  = array_key_exists('value', $in) ? $in['value'] : '';
$mode      = isset($in['mode']) ? strtolower(trim($in['mode'])) : 'equals'; // equals|icontains|istartswith|iendswith
$single    = isset($in['single']) ? (bool)$in['single'] : false;

if ($username === '' || $password === '' || $form_hash === '' || $keyReq === '') {
    respond(["ok"=>false,"error"=>"Missing required fields: username, password, form_hash, key"], 400);
}

$db = open_db();

// ---------- Auth ----------
$stmt = $db->prepare("SELECT username FROM users WHERE username=:u AND password=:p");
$stmt->bindValue(':u', $username, SQLITE3_TEXT);
$stmt->bindValue(':p', $password, SQLITE3_TEXT);
$auth = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
if (!$auth) respond(["ok"=>false,"error"=>"Invalid credentials"], 401);

// ---------- Form by hash & (optional) ownership ----------
$stmt = $db->prepare("SELECT id, title, hash FROM forms WHERE hash = :h");
$stmt->bindValue(':h', $form_hash, SQLITE3_TEXT);
$form = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
if (!$form) respond(["ok"=>false,"error"=>"Form not found for provided hash"], 404);

$ow = $db->prepare("SELECT username FROM form_owners WHERE form_id = :fid");
$ow->bindValue(':fid', $form['id'], SQLITE3_INTEGER);
$owner = $ow->execute()->fetchArray(SQLITE3_ASSOC);
if ($owner && $owner['username'] !== $username) {
    respond(["ok"=>false,"error"=>"You don't have access to this form"], 403);
}

// ---------- Load controls (we need exact field titles) ----------
$controls = [];
$sc = $db->prepare("SELECT field_title FROM controls WHERE form_id = :fid ORDER BY id ASC");
$sc->bindValue(':fid', $form['id'], SQLITE3_INTEGER);
$rc = $sc->execute();
while ($c = $rc->fetchArray(SQLITE3_ASSOC)) {
    $controls[] = $c['field_title'];
}

// ---------- Resolve requested key to an existing field_title ----------
$keyNorm = norm($keyReq);
$resolvedKey = null;

// 1) intento exacto normalizado
foreach ($controls as $ft) {
    if (norm($ft) === $keyNorm) { $resolvedKey = $ft; break; }
}
// 2) intento por similitud alta
if (!$resolvedKey) {
    foreach ($controls as $ft) {
        if (similar_enough(norm($ft), $keyNorm)) { $resolvedKey = $ft; break; }
    }
}
// 3) intento por contiene
if (!$resolvedKey) {
    foreach ($controls as $ft) {
        if (mb_strpos(norm($ft), $keyNorm) !== false) { $resolvedKey = $ft; break; }
    }
}

if (!$resolvedKey) {
    respond([
        "ok"=>false,
        "error"=>"Field key not found in this form",
        "hint"=>"Available keys",
        "keys"=>$controls
    ], 400);
}

// ---------- Fetch submissions and match ----------
$q = $db->prepare("SELECT id, form_id, unique_id, data, datetime, epoch, ip, user_agent, created_at
                   FROM submissions
                   WHERE form_id = :fid
                   ORDER BY id DESC");
$q->bindValue(':fid', $form['id'], SQLITE3_INTEGER);
$r = $q->execute();

$matches = [];
$valNorm = norm($valueReq);

while ($row = $r->fetchArray(SQLITE3_ASSOC)) {
    $payload = json_decode($row['data'], true);
    if (!is_array($payload)) $payload = [];

    if (!array_key_exists($resolvedKey, $payload)) continue;

    $candRaw = $payload[$resolvedKey];
    $candNorm = norm($candRaw);

    $ok = false;
    switch ($mode) {
        case 'icontains':   $ok = ($valNorm === '' ? true : (mb_strpos($candNorm, $valNorm) !== false)); break;
        case 'istartswith': $ok = ($valNorm === '' ? true : (mb_substr($candNorm, 0, mb_strlen($valNorm)) === $valNorm)); break;
        case 'iendswith':   $ok = ($valNorm === '' ? true : (mb_substr($candNorm, -mb_strlen($valNorm)) === $valNorm)); break;
        case 'equals':
        default:            $ok = ($candNorm === $valNorm); break;
    }
    if (!$ok) continue;

    // ---- row shape: flat object with all fields + metadata ----
    $flat = [
        "_id"         => (int)$row['id'],
        "_unique_id"  => $row['unique_id'],
        "_datetime"   => $row['datetime'],
        "_epoch"      => (int)$row['epoch'],
        "_ip"         => $row['ip'],
        "_user_agent" => $row['user_agent'],
        "_created_at" => $row['created_at']
    ];
    // añadir cada columna tal como se titula en controls
    foreach ($controls as $ft) {
        $flat[$ft] = array_key_exists($ft, $payload) ? $payload[$ft] : "";
    }
    $matches[] = $flat;

    if ($single) break; // suficiente con la primera
}

// ---------- Response ----------
if ($single) {
    if (count($matches) === 0) {
        respond([
            "ok"=>false,
            "form"=>["id"=>(int)$form['id'],"title"=>$form['title'],"hash"=>$form['hash']],
            "query"=>["key"=>$resolvedKey,"value"=>$valueReq,"mode"=>$mode,"single"=>true],
            "error"=>"No matching row found"
        ], 404);
    }
    respond([
        "ok"=>true,
        "form"=>["id"=>(int)$form['id'],"title"=>$form['title'],"hash"=>$form['hash']],
        "query"=>["key"=>$resolvedKey,"value"=>$valueReq,"mode"=>$mode,"single"=>true],
        "row"=>$matches[0] // objeto plano: todas las columnas
    ]);
} else {
    respond([
        "ok"=>true,
        "form"=>["id"=>(int)$form['id'],"title"=>$form['title'],"hash"=>$form['hash']],
        "query"=>["key"=>$resolvedKey,"value"=>$valueReq,"mode"=>$mode,"single"=>false],
        "rows"=>$matches,
        "count"=>count($matches),
        "columns"=>$controls
    ]);
}

