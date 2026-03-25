<?php
session_start();

/*
    jocarsa | lavender
    Consolidated index.php
    - Improved admin shell support
    - Left sidebar admin navigation
    - Explicit row report action
    - Corporate header
    - Keeps public forms, admin CRUD, submissions, and public check
*/

define('APP_NAME', 'jocarsa | lavender');

/* =========================================================
   Security
========================================================= */

function detect_malicious_input($data) {
    if (!is_string($data)) {
        return false;
    }

    $patterns = [
        '/<script.*?>.*?<\/script>/i',
        '/javascript:/i',
        '/on[a-z]+\s*=\s*"[^"]*"/i',
        '/\b(select|union|insert|update|delete|drop|alter|truncate)\b.*?(from|into|table|database)/i'
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $data)) {
            return true;
        }
    }
    return false;
}

function sanitize_input(&$input) {
    if (is_array($input)) {
        foreach ($input as &$value) {
            sanitize_input($value);
        }
    } else {
        if (detect_malicious_input($input)) {
            die("Security alert: Malicious input detected!");
        }
    }
}

$data = [
    'GET' => $_GET,
    'POST' => $_POST,
    'PUT' => [],
    'DELETE' => [],
    'RAW' => file_get_contents("php://input")
];

if ($_SERVER['REQUEST_METHOD'] === 'PUT' || $_SERVER['REQUEST_METHOD'] === 'DELETE') {
    parse_str($data['RAW'], $parsed_input);
    $data[$_SERVER['REQUEST_METHOD']] = $parsed_input;
}

foreach ($data as &$value) {
    sanitize_input($value);
}

/* =========================================================
   Database
========================================================= */

$db = new SQLite3('../databases/lavender.sqlite');
inicializar_db($db);

function inicializar_db($db) {
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )");

    $stmt = $db->prepare("SELECT COUNT(*) as count FROM users WHERE username = :username");
    $stmt->bindValue(':username', 'jocarsa', SQLITE3_TEXT);
    $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if ((int)$result['count'] === 0) {
        $db->exec("INSERT INTO users (username, password) VALUES ('jocarsa', 'jocarsa')");
    }

    $db->exec("CREATE TABLE IF NOT EXISTS forms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        hash TEXT UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    $db->exec("CREATE TABLE IF NOT EXISTS form_owners (
        form_id INTEGER PRIMARY KEY,
        username TEXT,
        FOREIGN KEY (form_id) REFERENCES forms(id)
    )");

    $db->exec("INSERT OR IGNORE INTO form_owners (form_id, username)
        SELECT id, 'jocarsa'
        FROM forms
        WHERE id NOT IN (SELECT form_id FROM form_owners)");

    $db->exec("CREATE TABLE IF NOT EXISTS controls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        form_id INTEGER,
        field_title TEXT,
        description TEXT,
        placeholder TEXT,
        type TEXT,
        min_length INTEGER,
        max_length INTEGER,
        required INTEGER DEFAULT 0,
        field_values TEXT
    )");

    $db->exec("CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        form_id INTEGER,
        unique_id TEXT,
        data TEXT,
        datetime TEXT,
        epoch INTEGER,
        ip TEXT,
        user_agent TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
}

/* =========================================================
   Auth / helpers
========================================================= */

function esta_logueado() {
    return isset($_SESSION['user']);
}

function requiere_login() {
    if (!esta_logueado()) {
        header("Location: ?admin=login");
        exit;
    }
}

function h($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function current_admin_action() {
    return isset($_GET['admin']) ? $_GET['admin'] : '';
}

function is_admin_view() {
    return isset($_GET['admin']) && $_GET['admin'] !== 'login';
}

/* =========================================================
   Layout
========================================================= */

function html_header($titulo = APP_NAME) {
    $isAdmin = is_admin_view();
    $loggedUser = isset($_SESSION['user']) ? $_SESSION['user'] : null;

    echo "<!DOCTYPE html>
<html lang='es'>
<head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <title>" . h($titulo) . "</title>
    <link rel='stylesheet' type='text/css' href='style.css' />
    <link rel='icon' type='image/png' href='https://static.jocarsa.com/logos/jocarsa%20%7C%20White.svg' />
</head>
<body>
<div id='wrapper'>
    <header id='header'>
        <div class='header-inner'>
            <div class='brand'>
                <img src='https://static.jocarsa.com/logos/jocarsa%20%7C%20White.svg' alt='Lavender'>
                <div class='brand-text'>
                    <h1>" . APP_NAME . "</h1>
                    <p>" . ($isAdmin ? "Panel de administración corporativo" : "Formularios y recogida de información") . "</p>
                </div>
            </div>
            <div class='header-right'>";

    if ($loggedUser) {
        echo "<span class='header-pill'>Usuario: <strong>" . h($loggedUser) . "</strong></span>";
    }

    echo "  </div>
        </div>
    </header>";
}

function html_footer() {
    echo "
    <footer id='footer'>
        <p>&copy; " . date('Y') . " " . APP_NAME . "</p>
    </footer>
</div>
</body>
</html>";
}

function admin_menu() {
    $current = current_admin_action();

    $items = [
        'dashboard' => ['🏠', 'Panel de control', '?admin=dashboard'],
        'newform' => ['➕', 'Nuevo formulario', '?admin=newform'],
    ];

    echo "<aside id='adminmenu'>
        <div class='adminmenu-head'>
            <h2>Administración</h2>
            <p>Acciones principales del sistema</p>
        </div>
        <ul>";

    foreach ($items as $key => $item) {
        $active = ($current === $key) ? "active" : "";
        echo "<li>
                <a class='{$active}' href='" . h($item[2]) . "'>
                    <span class='nav-icon'>" . $item[0] . "</span>
                    <span>" . h($item[1]) . "</span>
                </a>
              </li>";
    }

    echo "<li>
            <a href='?admin=logout'>
                <span class='nav-icon'>⎋</span>
                <span>Cerrar sesión</span>
            </a>
          </li>
        </ul>
    </aside>";
}

function admin_layout_start($title, $subtitle = '') {
    echo "<div class='admin-shell'>";
    admin_menu();
    echo "<main class='admin-content'>
            <section class='admin-card'>
                <div class='section-title'>
                    <div>
                        <h2>" . h($title) . "</h2>";
    if ($subtitle !== '') {
        echo "          <p>" . h($subtitle) . "</p>";
    }
    echo "          </div>
                </div>";
}

function admin_layout_end() {
    echo "  </section>
        </main>
    </div>";
}

/* =========================================================
   Routing
========================================================= */

if (isset($_GET['form'])) {
    manejar_formulario_publico($_GET['form']);
    exit;
} elseif (isset($_GET['admin'])) {
    manejar_admin();
    exit;
} elseif (isset($_GET['check'])) {
    mostrar_envio_publico($_GET['check']);
    exit;
} else {
    html_header("Bienvenido - " . APP_NAME);
    echo "<div id='content'>
            <div class='front-card' style='padding:28px;'>
                <h2>Bienvenido</h2>
                <p>Bienvenido a " . APP_NAME . ".</p>
                <p><a class='btn btn-primary' href='?admin=login'>Acceso Administrador</a></p>
            </div>
          </div>";
    html_footer();
    exit;
}

/* =========================================================
   Public form
========================================================= */

function manejar_formulario_publico($hash) {
    global $db;

    html_header("Completar Formulario - " . APP_NAME);

    $stmt = $db->prepare("SELECT * FROM forms WHERE hash = :hash");
    $stmt->bindValue(':hash', $hash, SQLITE3_TEXT);
    $form = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$form) {
        echo "<div id='content'><div class='front-card' style='padding:28px;'><p>Formulario no encontrado.</p></div></div>";
        html_footer();
        exit;
    }

    $stmt = $db->prepare("SELECT * FROM controls WHERE form_id = :form_id ORDER BY id ASC");
    $stmt->bindValue(':form_id', $form['id'], SQLITE3_INTEGER);
    $resultado = $stmt->execute();
    $controles = [];
    while ($row = $resultado->fetchArray(SQLITE3_ASSOC)) {
        $controles[] = $row;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!is_dir('media')) {
            mkdir('media', 0777, true);
        }

        $datos_envio = [];

        foreach ($controles as $control) {
            $nombre_campo = "campo_" . $control['id'];

            if ($control['type'] === 'none') {
                $datos_envio[$control['field_title']] = '';
                continue;
            }

            if ($control['type'] === 'checkbox') {
                if (isset($_POST[$nombre_campo]) && is_array($_POST[$nombre_campo])) {
                    $datos_envio[$control['field_title']] = implode(', ', $_POST[$nombre_campo]);
                } else {
                    $datos_envio[$control['field_title']] = '';
                }
                continue;
            }

            if ($control['type'] === 'file') {
                if (isset($_FILES[$nombre_campo]) && $_FILES[$nombre_campo]['error'] === UPLOAD_ERR_OK) {
                    $uploaded_file_name = uniqid() . '_' . basename($_FILES[$nombre_campo]['name']);
                    $destination = 'media/' . $uploaded_file_name;
                    if (move_uploaded_file($_FILES[$nombre_campo]['tmp_name'], $destination)) {
                        $datos_envio[$control['field_title']] = $destination;
                    } else {
                        $datos_envio[$control['field_title']] = 'Error al subir el archivo';
                    }
                } else {
                    $datos_envio[$control['field_title']] = '';
                }
                continue;
            }

            if ($control['type'] === 'radio' || $control['type'] === 'select') {
                $datos_envio[$control['field_title']] = isset($_POST[$nombre_campo]) ? $_POST[$nombre_campo] : '';
                continue;
            }

            $datos_envio[$control['field_title']] = isset($_POST[$nombre_campo]) ? $_POST[$nombre_campo] : '';
        }

        $unique_id = uniqid("env_", true);
        $submission_datetime = date("Y-m-d H:i:s");
        $submission_epoch = time();
        $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';

        $stmt = $db->prepare("INSERT INTO submissions (form_id, unique_id, data, datetime, epoch, ip, user_agent)
                              VALUES (:form_id, :unique_id, :data, :datetime, :epoch, :ip, :user_agent)");
        $stmt->bindValue(':form_id', $form['id'], SQLITE3_INTEGER);
        $stmt->bindValue(':unique_id', $unique_id, SQLITE3_TEXT);
        $stmt->bindValue(':data', json_encode($datos_envio, JSON_UNESCAPED_UNICODE), SQLITE3_TEXT);
        $stmt->bindValue(':datetime', $submission_datetime, SQLITE3_TEXT);
        $stmt->bindValue(':epoch', $submission_epoch, SQLITE3_INTEGER);
        $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
        $stmt->bindValue(':user_agent', $user_agent, SQLITE3_TEXT);
        $stmt->execute();

        echo "<div id='content'>
                <div class='front-card' style='padding:28px;'>
                    <p>Gracias por tu envío. Tu ID de envío es: <strong>" . h($unique_id) . "</strong></p>";

        $link = "?check=" . urlencode($unique_id);

        echo "      <p>Puedes ver o revisar tu envío aquí:
                        <a href='" . h($link) . "' target='_blank' id='publicSubmissionLink'>" . h($link) . "</a>
                    </p>
                    <button type='button' onclick='copiarAlPortapapeles()'>Copiar Enlace</button>
                </div>
              </div>";

        echo <<<HTML
<script>
function copiarAlPortapapeles() {
    var link = document.getElementById('publicSubmissionLink').href;
    navigator.clipboard.writeText(link).then(function() {
        alert('¡Enlace copiado al portapapeles!');
    }, function(err) {
        alert('Error al copiar el enlace');
    });
}
</script>
HTML;

        html_footer();
        exit;
    }

    echo "<div id='content'>";
    echo "<h2>" . h($form['title']) . "</h2>";
    echo "<form method='post' id='publicForm' enctype='multipart/form-data'>";

    foreach ($controles as $control) {
        echo "<div class='form-field" . ($control['type'] === 'none' ? " none-type" : "") . "'>";
        echo "<label>" . h($control['field_title']) . ($control['required'] ? " *" : "");
        if (!empty($control['description'])) {
            echo "<small>" . $control['description'] . "</small>";
        }
        echo "</label>";

        $nombre_campo = "campo_" . $control['id'];
        $atributos = "";

        if (!empty($control['min_length'])) {
            $atributos .= " minlength='" . intval($control['min_length']) . "'";
        }
        if (!empty($control['max_length'])) {
            $atributos .= " maxlength='" . intval($control['max_length']) . "'";
        }
        if (!empty($control['placeholder'])) {
            $atributos .= " placeholder='" . h($control['placeholder']) . "'";
        }
        if ((int)$control['required'] === 1) {
            $atributos .= " required";
        }

        switch ($control['type']) {
            case 'none':
                break;

            case 'textarea':
                echo "<textarea name='" . h($nombre_campo) . "' rows='4' {$atributos}></textarea>";
                break;

            case 'checkbox':
                $options = array_map('trim', explode(',', (string)$control['field_values']));
                echo "<div class='contieneopciones' style='width:100%;'>";
                foreach ($options as $opt) {
                    $optSafe = h($opt);
                    echo "<label><input type='checkbox' name='" . h($nombre_campo) . "[]' value='{$optSafe}'> {$optSafe}</label>";
                }
                echo "</div>";
                break;

            case 'radio':
                $options = array_map('trim', explode(',', (string)$control['field_values']));
                echo "<div class='contieneopciones' style='width:100%;'>";
                foreach ($options as $opt) {
                    $optSafe = h($opt);
                    echo "<label><input type='radio' name='" . h($nombre_campo) . "' value='{$optSafe}' {$atributos}> {$optSafe}</label>";
                }
                echo "</div>";
                break;

            case 'select':
                echo "<select name='" . h($nombre_campo) . "' {$atributos}>";
                $options = array_map('trim', explode(',', (string)$control['field_values']));
                foreach ($options as $opt) {
                    $optSafe = h($opt);
                    echo "<option value='{$optSafe}'>{$optSafe}</option>";
                }
                echo "</select>";
                break;

            case 'file':
                echo "<input type='file' name='" . h($nombre_campo) . "' {$atributos} />";
                break;

            case 'time':
                echo "<input type='time' name='" . h($nombre_campo) . "' {$atributos} />";
                break;

            case 'date':
                echo "<input type='date' name='" . h($nombre_campo) . "' {$atributos} />";
                break;

            case 'datetime':
            case 'datetime-local':
                echo "<input type='datetime-local' name='" . h($nombre_campo) . "' {$atributos} />";
                break;

            default:
                $type = h($control['type']);
                echo "<input type='{$type}' name='" . h($nombre_campo) . "' {$atributos} />";
                break;
        }

        echo "</div>";
    }

    echo "<div class='actions'><button type='submit'>Enviar</button></div>";
    echo "</form>";
    echo "</div>";

    html_footer();
}

/* =========================================================
   Admin routing
========================================================= */

function manejar_admin() {
    global $db;

    $accion = $_GET['admin'];

    if ($accion === 'login') {
        html_header("Acceso Administrador - " . APP_NAME);
        echo "<div class='login-wrap'>";
        echo "<form method='post' id='loginForm'>";
        echo "<h2>Acceso administrador</h2>";
        echo "<p>Introduce tus credenciales para acceder al panel de control.</p>";

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $usuario = isset($_POST['username']) ? $_POST['username'] : '';
            $clave = isset($_POST['password']) ? $_POST['password'] : '';

            $stmt = $db->prepare("SELECT * FROM users WHERE username = :username AND password = :password");
            $stmt->bindValue(':username', $usuario, SQLITE3_TEXT);
            $stmt->bindValue(':password', $clave, SQLITE3_TEXT);
            $resultado = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

            if ($resultado) {
                $_SESSION['user'] = $usuario;
                header("Location: ?admin=dashboard");
                exit;
            } else {
                echo "<p class='error'>Credenciales inválidas.</p>";
            }
        }

        echo "<div class='form-field'><label>Usuario</label><input type='text' name='username' required></div>";
        echo "<div class='form-field'><label>Contraseña</label><input type='password' name='password' required></div>";
        echo "<div class='actions'><button type='submit'>Iniciar sesión</button></div>";
        echo "</form>";
        echo "</div>";
        html_footer();
        exit;
    }

    if ($accion === 'logout') {
        session_destroy();
        header("Location: ?admin=login");
        exit;
    }

    if ($accion === 'viewsubmission' || $accion === 'reportsubmission') {
        if (!isset($_GET['id'])) {
            echo "ID de envío no especificado.";
            exit;
        }
        admin_view_submission((int)$_GET['id']);
        exit;
    }

    if ($accion === 'deletesubmission') {
        if (!isset($_GET['id'])) {
            echo "ID de envío no especificado.";
            exit;
        }
        admin_delete_submission((int)$_GET['id']);
        exit;
    }

    requiere_login();

    if ($accion === 'dashboard') {
        admin_dashboard();
        exit;
    } elseif ($accion === 'newform') {
        admin_new_form();
        exit;
    } elseif ($accion === 'editform') {
        if (!isset($_GET['id'])) {
            echo "ID del formulario no especificado.";
            exit;
        }
        admin_edit_form((int)$_GET['id']);
        exit;
    } elseif ($accion === 'viewsubmissions') {
        if (!isset($_GET['id'])) {
            echo "ID del formulario no especificado.";
            exit;
        }
        admin_view_submissions((int)$_GET['id']);
        exit;
    } elseif ($accion === 'deleteform') {
        if (!isset($_GET['id'])) {
            echo "ID del formulario no especificado.";
            exit;
        }
        admin_delete_form((int)$_GET['id']);
        exit;
    } elseif ($accion === 'editfield') {
        if (!isset($_GET['id'])) {
            echo "ID del campo no especificado.";
            exit;
        }
        admin_edit_field((int)$_GET['id']);
        exit;
    } elseif ($accion === 'deletefield') {
        if (!isset($_GET['id'])) {
            echo "ID del campo no especificado.";
            exit;
        }
        admin_delete_field((int)$_GET['id']);
        exit;
    } else {
        echo "Acción administrativa desconocida.";
        exit;
    }
}

/* =========================================================
   Admin pages
========================================================= */

function admin_dashboard() {
    global $db;

    html_header("Panel de Control - " . APP_NAME);
    admin_layout_start("Tus formularios", "Gestiona formularios, accesos y envíos desde un entorno lateral estilo panel profesional.");

    $currentUser = $_SESSION['user'];
    $stmt = $db->prepare("SELECT f.* FROM forms f
                          JOIN form_owners fo ON f.id = fo.form_id
                          WHERE fo.username = :username
                          ORDER BY f.id DESC");
    $stmt->bindValue(':username', $currentUser, SQLITE3_TEXT);
    $resultado = $stmt->execute();

    echo "<div class='actions' style='margin-bottom:18px;'>
            <a class='btn btn-primary' href='?admin=newform'>➕ Crear formulario</a>
          </div>";

    echo "<div class='table-wrap'>
            <table>
                <tr>
                    <th>ID</th>
                    <th>Título</th>
                    <th>Hash</th>
                    <th>Acciones</th>
                </tr>";

    while ($row = $resultado->fetchArray(SQLITE3_ASSOC)) {
        echo "<tr>";
        echo "<td>" . h($row['id']) . "</td>";
        echo "<td><strong>" . h($row['title']) . "</strong></td>";
        echo "<td><code>" . h($row['hash']) . "</code></td>";
        echo "<td>
                <div class='table-actions'>
                    <a href='?admin=editform&id=" . (int)$row['id'] . "'>Editar</a>
                    <a href='?admin=viewsubmissions&id=" . (int)$row['id'] . "'>Envíos</a>
                    <a href='?form=" . h($row['hash']) . "' target='_blank'>Abrir</a>
                    <a class='danger' href='?admin=deleteform&id=" . (int)$row['id'] . "' onclick='return confirm(\"¿Eliminar este formulario?\")'>Eliminar</a>
                </div>
              </td>";
        echo "</tr>";
    }

    echo "  </table>
          </div>";

    admin_layout_end();
    html_footer();
}

function admin_new_form() {
    global $db;

    html_header("Crear Nuevo Formulario - " . APP_NAME);

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $titulo = isset($_POST['title']) ? trim($_POST['title']) : '';

        $stmt = $db->prepare("INSERT INTO forms (title, hash) VALUES (:title, '')");
        $stmt->bindValue(':title', $titulo, SQLITE3_TEXT);
        $stmt->execute();

        $form_id = $db->lastInsertRowID();
        $hash = md5($form_id . time() . rand());

        $stmt = $db->prepare("UPDATE forms SET hash = :hash WHERE id = :id");
        $stmt->bindValue(':hash', $hash, SQLITE3_TEXT);
        $stmt->bindValue(':id', $form_id, SQLITE3_INTEGER);
        $stmt->execute();

        $currentUser = isset($_SESSION['user']) ? $_SESSION['user'] : 'jocarsa';
        $stmt = $db->prepare("INSERT INTO form_owners (form_id, username) VALUES (:form_id, :username)");
        $stmt->bindValue(':form_id', $form_id, SQLITE3_INTEGER);
        $stmt->bindValue(':username', $currentUser, SQLITE3_TEXT);
        $stmt->execute();

        header("Location: ?admin=editform&id=" . $form_id);
        exit;
    }

    admin_layout_start("Crear formulario", "Define un nuevo formulario y después añade sus campos.");

    echo "<form method='post' id='newForm'>
            <div class='form-field'>
                <label for='title'>Título del formulario</label>
                <input type='text' id='title' name='title' required>
            </div>
            <div class='actions'>
                <button type='submit'>Crear formulario</button>
                <a class='btn btn-secondary' href='?admin=dashboard'>Volver</a>
            </div>
          </form>";

    admin_layout_end();
    html_footer();
}

function admin_edit_form($form_id) {
    global $db;

    $stmt = $db->prepare("SELECT username FROM form_owners WHERE form_id = :form_id");
    $stmt->bindValue(':form_id', $form_id, SQLITE3_INTEGER);
    $owner = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$owner || $owner['username'] !== $_SESSION['user']) {
        echo "No tienes permiso para editar este formulario.";
        exit;
    }

    $stmt = $db->prepare("SELECT * FROM forms WHERE id = :id");
    $stmt->bindValue(':id', $form_id, SQLITE3_INTEGER);
    $form = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$form) {
        echo "Formulario no encontrado.";
        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['field_title'])) {
        $field_title = isset($_POST['field_title']) ? trim($_POST['field_title']) : '';
        $description = isset($_POST['description']) ? $_POST['description'] : '';
        $placeholder = isset($_POST['placeholder']) ? $_POST['placeholder'] : '';
        $required = isset($_POST['required']) ? 1 : 0;
        $type = isset($_POST['type']) ? $_POST['type'] : 'text';
        $min_length = ($_POST['min_length'] !== '') ? (int)$_POST['min_length'] : null;
        $max_length = ($_POST['max_length'] !== '') ? (int)$_POST['max_length'] : null;
        $values = isset($_POST['values']) ? $_POST['values'] : '';

        $stmt = $db->prepare("
            INSERT INTO controls
            (form_id, field_title, description, placeholder, type, min_length, max_length, required, field_values)
            VALUES
            (:form_id, :field_title, :description, :placeholder, :type, :min_length, :max_length, :required, :field_values)
        ");

        $stmt->bindValue(':form_id', $form_id, SQLITE3_INTEGER);
        $stmt->bindValue(':field_title', $field_title, SQLITE3_TEXT);
        $stmt->bindValue(':description', $description, SQLITE3_TEXT);
        $stmt->bindValue(':placeholder', $placeholder, SQLITE3_TEXT);
        $stmt->bindValue(':type', $type, SQLITE3_TEXT);

        if ($min_length !== null) {
            $stmt->bindValue(':min_length', $min_length, SQLITE3_INTEGER);
        } else {
            $stmt->bindValue(':min_length', null, SQLITE3_NULL);
        }

        if ($max_length !== null) {
            $stmt->bindValue(':max_length', $max_length, SQLITE3_INTEGER);
        } else {
            $stmt->bindValue(':max_length', null, SQLITE3_NULL);
        }

        $stmt->bindValue(':required', $required, SQLITE3_INTEGER);
        $stmt->bindValue(':field_values', $values, SQLITE3_TEXT);
        $stmt->execute();

        header("Location: ?admin=editform&id=" . $form_id);
        exit;
    }

    html_header("Editar Formulario: " . $form['title'] . " - " . APP_NAME);
    admin_layout_start("Editar formulario", $form['title']);

    echo "<p class='url'>URL pública: <a href='?form=" . h($form['hash']) . "' target='_blank'>?form=" . h($form['hash']) . "</a></p>";

    echo "<div class='admin-card' style='padding:0; box-shadow:none; border:none; background:transparent;'>
            <h3 style='margin:0 0 18px 0; color:var(--lavender-900);'>Agregar nuevo campo</h3>
            <form method='post' id='newControl'>
                <div class='form-field'>
                    <label>Título del campo</label>
                    <input type='text' name='field_title' required>
                </div>

                <div class='form-field'>
                    <label>Descripción</label>
                    <textarea name='description'></textarea>
                </div>

                <div class='form-field'>
                    <label>Placeholder</label>
                    <input type='text' name='placeholder'>
                </div>

                <div class='form-field'>
                    <label>Obligatorio</label>
                    <div><label><input type='checkbox' name='required' value='1'> Sí</label></div>
                </div>

                <div class='form-field'>
                    <label>Tipo</label>
                    <select name='type'>
                        <option value='none'>Ninguno (solo texto)</option>
                        <option value='text'>Texto</option>
                        <option value='textarea'>Área de Texto</option>
                        <option value='number'>Número</option>
                        <option value='email'>Correo</option>
                        <option value='date'>Fecha</option>
                        <option value='time'>Hora</option>
                        <option value='datetime-local'>Fecha y Hora</option>
                        <option value='password'>Contraseña</option>
                        <option value='url'>URL</option>
                        <option value='checkbox'>Checkbox(es)</option>
                        <option value='radio'>Radio</option>
                        <option value='select'>Select</option>
                        <option value='file'>Archivo</option>
                    </select>
                </div>

                <div class='form-field'>
                    <label>Valores</label>
                    <input type='text' name='values'>
                </div>

                <div class='form-field'>
                    <label>Longitud mínima</label>
                    <input type='number' name='min_length' min='0'>
                </div>

                <div class='form-field'>
                    <label>Longitud máxima</label>
                    <input type='number' name='max_length' min='0'>
                </div>

                <div class='actions'>
                    <button type='submit'>Agregar campo</button>
                    <a class='btn btn-secondary' href='?admin=dashboard'>Volver</a>
                </div>
            </form>
          </div>";

    echo "<div class='admin-card' style='margin-top:22px;'>
            <div class='section-title'>
                <div>
                    <h2>Campos actuales</h2>
                    <p>Listado de elementos del formulario</p>
                </div>
            </div>";

    $stmt = $db->prepare("SELECT * FROM controls WHERE form_id = :form_id ORDER BY id ASC");
    $stmt->bindValue(':form_id', $form_id, SQLITE3_INTEGER);
    $resultado = $stmt->execute();

    echo "<ul class='control-list'>";
    while ($row = $resultado->fetchArray(SQLITE3_ASSOC)) {
        echo "<li>";
        echo "<strong>" . h($row['field_title']) . "</strong> <span class='muted'>(" . h($row['type']) . ")</span><br>";
        if (!empty($row['description'])) {
            echo "<div class='muted' style='margin-top:8px;'>" . h($row['description']) . "</div>";
        }
        if (!empty($row['field_values'])) {
            echo "<div class='muted' style='margin-top:8px;'>Valores: " . h($row['field_values']) . "</div>";
        }
        echo "<div class='actions' style='margin-top:12px;'>
                <a class='btn btn-secondary' href='?admin=editfield&id=" . (int)$row['id'] . "'>Editar</a>
                <a class='btn btn-danger' href='?admin=deletefield&id=" . (int)$row['id'] . "' onclick='return confirm(\"¿Eliminar este campo?\")'>Eliminar</a>
              </div>";
        echo "</li>";
    }
    echo "</ul>";
    echo "</div>";

    admin_layout_end();
    html_footer();
}

function admin_edit_field($field_id) {
    global $db;

    $stmt = $db->prepare("SELECT c.*, f.title as form_title, f.id as form_id
                          FROM controls c
                          JOIN forms f ON c.form_id = f.id
                          WHERE c.id = :id");
    $stmt->bindValue(':id', $field_id, SQLITE3_INTEGER);
    $field = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$field) {
        echo "Campo no encontrado.";
        exit;
    }

    $stmt = $db->prepare("SELECT username FROM form_owners WHERE form_id = :form_id");
    $stmt->bindValue(':form_id', $field['form_id'], SQLITE3_INTEGER);
    $owner = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$owner || $owner['username'] !== $_SESSION['user']) {
        echo "No tienes permiso para editar este campo.";
        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $field_title = isset($_POST['field_title']) ? trim($_POST['field_title']) : '';
        $description = isset($_POST['description']) ? $_POST['description'] : '';
        $placeholder = isset($_POST['placeholder']) ? $_POST['placeholder'] : '';
        $required = isset($_POST['required']) ? 1 : 0;
        $type = isset($_POST['type']) ? $_POST['type'] : 'text';
        $min_length = ($_POST['min_length'] !== '') ? (int)$_POST['min_length'] : null;
        $max_length = ($_POST['max_length'] !== '') ? (int)$_POST['max_length'] : null;
        $values = isset($_POST['values']) ? $_POST['values'] : '';

        $stmt = $db->prepare("
            UPDATE controls SET
                field_title = :field_title,
                description = :description,
                placeholder = :placeholder,
                type = :type,
                min_length = :min_length,
                max_length = :max_length,
                required = :required,
                field_values = :field_values
            WHERE id = :id
        ");

        $stmt->bindValue(':field_title', $field_title, SQLITE3_TEXT);
        $stmt->bindValue(':description', $description, SQLITE3_TEXT);
        $stmt->bindValue(':placeholder', $placeholder, SQLITE3_TEXT);
        $stmt->bindValue(':type', $type, SQLITE3_TEXT);

        if ($min_length !== null) {
            $stmt->bindValue(':min_length', $min_length, SQLITE3_INTEGER);
        } else {
            $stmt->bindValue(':min_length', null, SQLITE3_NULL);
        }

        if ($max_length !== null) {
            $stmt->bindValue(':max_length', $max_length, SQLITE3_INTEGER);
        } else {
            $stmt->bindValue(':max_length', null, SQLITE3_NULL);
        }

        $stmt->bindValue(':required', $required, SQLITE3_INTEGER);
        $stmt->bindValue(':field_values', $values, SQLITE3_TEXT);
        $stmt->bindValue(':id', $field_id, SQLITE3_INTEGER);
        $stmt->execute();

        header("Location: ?admin=editform&id=" . (int)$field['form_id']);
        exit;
    }

    html_header("Editar campo - " . APP_NAME);
    admin_layout_start("Editar campo", $field['form_title']);

    echo "<form method='post'>
            <div class='form-field'>
                <label>Título del campo</label>
                <input type='text' name='field_title' value='" . h($field['field_title']) . "' required>
            </div>

            <div class='form-field'>
                <label>Descripción</label>
                <textarea name='description'>" . h($field['description']) . "</textarea>
            </div>

            <div class='form-field'>
                <label>Placeholder</label>
                <input type='text' name='placeholder' value='" . h($field['placeholder']) . "'>
            </div>

            <div class='form-field'>
                <label>Obligatorio</label>
                <div><label><input type='checkbox' name='required' value='1' " . ((int)$field['required'] === 1 ? 'checked' : '') . "> Sí</label></div>
            </div>

            <div class='form-field'>
                <label>Tipo</label>
                <select name='type'>";

    $types = ['none','text','textarea','number','email','date','time','datetime-local','password','url','checkbox','radio','select','file'];
    foreach ($types as $type) {
        $selected = ($field['type'] === $type) ? 'selected' : '';
        echo "<option value='" . h($type) . "' {$selected}>" . h($type) . "</option>";
    }

    echo "  </select>
            </div>

            <div class='form-field'>
                <label>Valores</label>
                <input type='text' name='values' value='" . h($field['field_values']) . "'>
            </div>

            <div class='form-field'>
                <label>Longitud mínima</label>
                <input type='number' name='min_length' min='0' value='" . h($field['min_length']) . "'>
            </div>

            <div class='form-field'>
                <label>Longitud máxima</label>
                <input type='number' name='max_length' min='0' value='" . h($field['max_length']) . "'>
            </div>

            <div class='actions'>
                <button type='submit'>Guardar cambios</button>
                <a class='btn btn-secondary' href='?admin=editform&id=" . (int)$field['form_id'] . "'>Volver</a>
            </div>
          </form>";

    admin_layout_end();
    html_footer();
}

function admin_delete_field($field_id) {
    global $db;

    $stmt = $db->prepare("SELECT form_id FROM controls WHERE id = :id");
    $stmt->bindValue(':id', $field_id, SQLITE3_INTEGER);
    $field = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$field) {
        echo "Campo no encontrado.";
        exit;
    }

    $stmt = $db->prepare("SELECT username FROM form_owners WHERE form_id = :form_id");
    $stmt->bindValue(':form_id', $field['form_id'], SQLITE3_INTEGER);
    $owner = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$owner || $owner['username'] !== $_SESSION['user']) {
        echo "No tienes permiso para eliminar este campo.";
        exit;
    }

    $stmt = $db->prepare("DELETE FROM controls WHERE id = :id");
    $stmt->bindValue(':id', $field_id, SQLITE3_INTEGER);
    $stmt->execute();

    header("Location: ?admin=editform&id=" . (int)$field['form_id']);
    exit;
}

function admin_view_submissions($form_id) {
    global $db;

    $stmt = $db->prepare("SELECT username FROM form_owners WHERE form_id = :form_id");
    $stmt->bindValue(':form_id', $form_id, SQLITE3_INTEGER);
    $owner = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$owner || $owner['username'] !== $_SESSION['user']) {
        echo "No tienes permiso para ver los envíos de este formulario.";
        exit;
    }

    $stmt = $db->prepare("SELECT * FROM forms WHERE id = :id");
    $stmt->bindValue(':id', $form_id, SQLITE3_INTEGER);
    $form = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$form) {
        echo "Formulario no encontrado.";
        exit;
    }

    $controls = [];
    $stmt = $db->prepare("SELECT * FROM controls WHERE form_id = :form_id ORDER BY id ASC");
    $stmt->bindValue(':form_id', $form_id, SQLITE3_INTEGER);
    $resultControls = $stmt->execute();
    while ($ctrl = $resultControls->fetchArray(SQLITE3_ASSOC)) {
        $controls[] = $ctrl;
    }

    html_header("Envíos para " . $form['title'] . " - " . APP_NAME);
    admin_layout_start("Envíos del formulario", $form['title']);

    echo "<div class='table-wrap'>";
    echo "<table id='submissionsTable'>";
    echo "<thead><tr>";
    echo "<th>ID</th>";
    echo "<th>ID único</th>";

    foreach ($controls as $ctrl) {
        echo "<th>" . h($ctrl['field_title']) . "</th>";
    }

    echo "<th>Fecha</th>";
    echo "<th>Epoch</th>";
    echo "<th>IP</th>";
    echo "<th>User Agent</th>";
    echo "<th>Acciones</th>";
    echo "</tr></thead><tbody>";

    $query = "SELECT * FROM submissions WHERE form_id = " . intval($form_id) . " ORDER BY id DESC";
    $result = $db->query($query);

    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $data = json_decode($row['data'], true);
        if (!is_array($data)) {
            $data = [];
        }

        echo "<tr>";
        echo "<td>" . h($row['id']) . "</td>";
        echo "<td>" . h($row['unique_id']) . "</td>";

        foreach ($controls as $ctrl) {
            $fieldTitle = $ctrl['field_title'];
            $value = isset($data[$fieldTitle]) ? $data[$fieldTitle] : "";

            if ($ctrl['type'] === 'file' && strpos((string)$value, 'media/') === 0) {
                $filename = basename($value);
                echo "<td><a href='" . h($value) . "' target='_blank'>" . h($filename) . "</a></td>";
            } elseif ($ctrl['type'] === 'textarea') {
                $preview = mb_substr(strip_tags((string)$value), 0, 50);
                echo "<td>" . h($preview) . (mb_strlen((string)$value) > 50 ? '...' : '') . "</td>";
            } else {
                echo "<td>" . h($value) . "</td>";
            }
        }

        echo "<td>" . h($row['datetime']) . "</td>";
        echo "<td>" . h($row['epoch']) . "</td>";
        echo "<td>" . h($row['ip']) . "</td>";
        echo "<td>" . h($row['user_agent']) . "</td>";
        echo "<td>
                <div class='table-actions'>
                    <a href='?admin=reportsubmission&id=" . (int)$row['id'] . "'>Reporte</a>
                    <a href='?admin=viewsubmission&id=" . (int)$row['id'] . "'>Detalle</a>
                    <a class='danger' href='?admin=deletesubmission&id=" . (int)$row['id'] . "' onclick='return confirm(\"¿Eliminar este envío?\")'>Eliminar</a>
                </div>
              </td>";
        echo "</tr>";
    }

    echo "</tbody></table>";
    echo "</div>";

    admin_layout_end();
    html_footer();
}

function admin_view_submission($submission_id) {
    global $db;

    $stmt = $db->prepare("SELECT * FROM submissions WHERE id = :id");
    $stmt->bindValue(':id', $submission_id, SQLITE3_INTEGER);
    $submission = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$submission) {
        echo "Envío no encontrado.";
        exit;
    }

    $stmt = $db->prepare("SELECT username FROM form_owners WHERE form_id = :form_id");
    $stmt->bindValue(':form_id', $submission['form_id'], SQLITE3_INTEGER);
    $owner = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$owner || $owner['username'] !== $_SESSION['user']) {
        echo "No tienes permiso para ver este envío.";
        exit;
    }

    $stmt = $db->prepare("SELECT * FROM forms WHERE id = :id");
    $stmt->bindValue(':id', $submission['form_id'], SQLITE3_INTEGER);
    $form = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    html_header("Reporte del envío - " . APP_NAME);
    admin_layout_start("Reporte del envío", isset($form['title']) ? $form['title'] : 'Formulario');

    echo "<div class='report-meta'>
            <div class='meta-box'><span class='k'>ID interno</span><span class='v'>" . h($submission['id']) . "</span></div>
            <div class='meta-box'><span class='k'>ID de envío</span><span class='v'>" . h($submission['unique_id']) . "</span></div>
            <div class='meta-box'><span class='k'>Fecha y hora</span><span class='v'>" . h($submission['datetime']) . "</span></div>
            <div class='meta-box'><span class='k'>Epoch</span><span class='v'>" . h($submission['epoch']) . "</span></div>
            <div class='meta-box'><span class='k'>IP</span><span class='v'>" . h($submission['ip']) . "</span></div>
            <div class='meta-box'><span class='k'>User Agent</span><span class='v'>" . h($submission['user_agent']) . "</span></div>
          </div>";

    $data = json_decode($submission['data'], true);

    if (is_array($data)) {
        echo "<div class='submission-report'>";
        foreach ($data as $label => $value) {
            echo "<div class='submission-field'>";
            echo "<span class='submission-label'>" . h($label) . "</span>";
            echo "<div>";
            if (is_string($value) && strpos($value, 'media/') === 0) {
                $filename = basename($value);
                echo "<a href='" . h($value) . "' target='_blank'>" . h($filename) . "</a>";
            } else {
                echo nl2br(h((string)$value));
            }
            echo "</div>";
            echo "</div>";
        }
        echo "</div>";
    } else {
        echo "<div class='submission-report'><p>" . h($submission['data']) . "</p></div>";
    }

    echo "<div class='actions' style='margin-top:18px;'>
            <a class='btn btn-secondary' href='?admin=viewsubmissions&id=" . (int)$submission['form_id'] . "'>Volver a envíos</a>
            <a class='btn btn-danger' href='?admin=deletesubmission&id=" . (int)$submission['id'] . "' onclick='return confirm(\"¿Eliminar este envío?\")'>Eliminar envío</a>
          </div>";

    admin_layout_end();
    html_footer();
}

function admin_delete_submission($submission_id) {
    global $db;

    $stmt = $db->prepare("SELECT * FROM submissions WHERE id = :id");
    $stmt->bindValue(':id', $submission_id, SQLITE3_INTEGER);
    $submission = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$submission) {
        echo "Envío no encontrado.";
        exit;
    }

    $stmt = $db->prepare("SELECT username FROM form_owners WHERE form_id = :form_id");
    $stmt->bindValue(':form_id', $submission['form_id'], SQLITE3_INTEGER);
    $owner = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$owner || $owner['username'] !== $_SESSION['user']) {
        echo "No tienes permiso para eliminar este envío.";
        exit;
    }

    $stmt = $db->prepare("DELETE FROM submissions WHERE id = :id");
    $stmt->bindValue(':id', $submission_id, SQLITE3_INTEGER);
    $stmt->execute();

    header("Location: ?admin=viewsubmissions&id=" . (int)$submission['form_id']);
    exit;
}

function admin_delete_form($form_id) {
    global $db;

    $stmt = $db->prepare("SELECT username FROM form_owners WHERE form_id = :form_id");
    $stmt->bindValue(':form_id', $form_id, SQLITE3_INTEGER);
    $owner = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    if (!$owner || $owner['username'] !== $_SESSION['user']) {
        echo "No tienes permiso para eliminar este formulario.";
        exit;
    }

    $stmt = $db->prepare("DELETE FROM controls WHERE form_id = :form_id");
    $stmt->bindValue(':form_id', $form_id, SQLITE3_INTEGER);
    $stmt->execute();

    $stmt = $db->prepare("DELETE FROM submissions WHERE form_id = :form_id");
    $stmt->bindValue(':form_id', $form_id, SQLITE3_INTEGER);
    $stmt->execute();

    $stmt = $db->prepare("DELETE FROM form_owners WHERE form_id = :form_id");
    $stmt->bindValue(':form_id', $form_id, SQLITE3_INTEGER);
    $stmt->execute();

    $stmt = $db->prepare("DELETE FROM forms WHERE id = :id");
    $stmt->bindValue(':id', $form_id, SQLITE3_INTEGER);
    $stmt->execute();

    header("Location: ?admin=dashboard");
    exit;
}

/* =========================================================
   Public submission check
========================================================= */

function mostrar_envio_publico($unique_id) {
    global $db;

    $stmt = $db->prepare("SELECT s.*, f.title AS form_title
                          FROM submissions s
                          LEFT JOIN forms f ON s.form_id = f.id
                          WHERE s.unique_id = :unique_id
                          LIMIT 1");
    $stmt->bindValue(':unique_id', $unique_id, SQLITE3_TEXT);
    $submission = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

    html_header("Consulta de envío - " . APP_NAME);

    echo "<div id='content'>";

    if (!$submission) {
        echo "<div class='front-card' style='padding:28px;'><p>Envío no encontrado.</p></div>";
        echo "</div>";
        html_footer();
        exit;
    }

    echo "<div class='front-card' style='padding:28px; margin-bottom:22px;'>
            <h2>Consulta de envío</h2>
            <div class='report-meta'>
                <div class='meta-box'><span class='k'>Formulario</span><span class='v'>" . h($submission['form_title']) . "</span></div>
                <div class='meta-box'><span class='k'>ID de envío</span><span class='v'>" . h($submission['unique_id']) . "</span></div>
                <div class='meta-box'><span class='k'>Fecha y hora</span><span class='v'>" . h($submission['datetime']) . "</span></div>
            </div>
          </div>";

    $data = json_decode($submission['data'], true);

    echo "<div class='submission-report'>";
    if (is_array($data)) {
        foreach ($data as $label => $value) {
            echo "<div class='submission-field'>";
            echo "<span class='submission-label'>" . h($label) . "</span>";
            echo "<div>";
            if (is_string($value) && strpos($value, 'media/') === 0) {
                $filename = basename($value);
                echo "<a href='" . h($value) . "' target='_blank'>" . h($filename) . "</a>";
            } else {
                echo nl2br(h((string)$value));
            }
            echo "</div>";
            echo "</div>";
        }
    } else {
        echo "<p>No hay datos disponibles.</p>";
    }
    echo "</div>";

    echo "</div>";
    html_footer();
}
