<?php
session_start();

define('APP_NAME', 'jocarsa | lavender');

// Open (or create) the SQLite database in the same directory
$db = new SQLite3('db.sqlite');

// Initialize the DB (create tables if needed, add default user, etc.)
inicializar_db($db);

function inicializar_db($db) {
    // Users table
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )");

    // Default admin user
    $stmt = $db->prepare("SELECT COUNT(*) as count FROM users WHERE username = :username");
    $stmt->bindValue(':username', 'jocarsa', SQLITE3_TEXT);
    $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if ($result['count'] == 0) {
        $db->exec("INSERT INTO users (username, password) VALUES ('jocarsa', 'jocarsa')");
    }

    // Forms table
    $db->exec("CREATE TABLE IF NOT EXISTS forms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        hash TEXT UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    // Controls table (fields)
    // Using field_values instead of "values" (reserved word)
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

    // Submissions table
    // Added new fields: datetime, epoch, ip, and user_agent
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

// ---------------------
// Helper Functions
// ---------------------
function esta_logueado() {
    return isset($_SESSION['user']);
}

function requiere_login() {
    if (!esta_logueado()) {
        header("Location: ?admin=login");
        exit;
    }
}

function html_header($titulo = APP_NAME) {
    echo "<!DOCTYPE html>
<html lang='es'>
<head>
  <meta charset='utf-8'>
  <title>" . htmlspecialchars($titulo) . "</title>
  <link rel='stylesheet' type='text/css' href='style.css' />
  <link rel='icon' type='image/svg+xml' href='lavender.png' />
</head>
<body>
<div id='wrapper'>
  <header id='header'>
    <h1><img src='lavender.png'>" . APP_NAME . "</h1>
  </header>
";
}

function html_footer() {
    echo "
  <footer id='footer'>
    <p>&copy; " . date("Y") . " " . APP_NAME . "</p>
  </footer>
</div> <!-- Fin wrapper -->
</body>
</html>";
}

function admin_menu() {
    echo "<nav id='adminmenu'>
      <ul>
        <li><a href='?admin=dashboard'>Panel de Control</a></li>
        <li><a href='?admin=newform'>Nuevo Formulario</a></li>
        <li><a href='?admin=logout'>Cerrar Sesión</a></li>
      </ul>
    </nav>";
}

// ---------------------
// Routing
// ---------------------
if (isset($_GET['form'])) {
    $form_hash = $_GET['form'];
    manejar_formulario_publico($form_hash);
    exit;
} elseif (isset($_GET['admin'])) {
    manejar_admin();
    exit;
} else {
    html_header("Bienvenido - " . APP_NAME);
    echo "<div id='content'>
            <p>Bienvenido a " . APP_NAME . ".</p>
            <p><a href='?admin=login'>Acceso Administrador</a></p>
          </div>";
    html_footer();
    exit;
}

// ---------------------
// Public Form Handler
// ---------------------
function manejar_formulario_publico($hash) {
    global $db;
    html_header("Completar Formulario - " . APP_NAME);

    // Find the form by its unique hash
    $stmt = $db->prepare("SELECT * FROM forms WHERE hash = :hash");
    $stmt->bindValue(':hash', $hash, SQLITE3_TEXT);
    $form = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if (!$form) {
        echo "<div id='content'><p>Formulario no encontrado.</p></div>";
        html_footer();
        exit;
    }

    // Get all controls for this form
    $stmt = $db->prepare("SELECT * FROM controls WHERE form_id = :form_id");
    $stmt->bindValue(':form_id', $form['id'], SQLITE3_INTEGER);
    $resultado = $stmt->execute();
    $controles = [];
    while ($row = $resultado->fetchArray(SQLITE3_ASSOC)) {
         $controles[] = $row;
    }

    // Always use multipart/form-data (for possible file uploads)
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
         // Ensure the "media" folder exists for file uploads
         if (!is_dir('media')) {
             mkdir('media');
         }

         $datos_envio = [];
         foreach ($controles as $control) {
             $nombre_campo = "campo_" . $control['id'];

             // If type=none, no input is shown—store empty or skip
             if ($control['type'] === 'none') {
                 $datos_envio[$control['field_title']] = '';
                 continue;
             }

             // Checkbox can return an array if multiple are selected
             if ($control['type'] === 'checkbox') {
                 if (isset($_POST[$nombre_campo]) && is_array($_POST[$nombre_campo])) {
                     $datos_envio[$control['field_title']] = implode(', ', $_POST[$nombre_campo]);
                 } else {
                     $datos_envio[$control['field_title']] = '';
                 }
                 continue;
             }

             // File input
             if ($control['type'] === 'file') {
                 if (isset($_FILES[$nombre_campo]) && $_FILES[$nombre_campo]['error'] === UPLOAD_ERR_OK) {
                     $uploaded_file_name = uniqid() . '_' . basename($_FILES[$nombre_campo]['name']);
                     $destination = 'media/' . $uploaded_file_name;
                     if (move_uploaded_file($_FILES[$nombre_campo]['tmp_name'], $destination)) {
                         // Store the file path
                         $datos_envio[$control['field_title']] = $destination;
                     } else {
                         $datos_envio[$control['field_title']] = 'Error al subir el archivo';
                     }
                 } else {
                     $datos_envio[$control['field_title']] = '';
                 }
                 continue;
             }

             // Radio or select
             if ($control['type'] === 'radio' || $control['type'] === 'select') {
                 if (isset($_POST[$nombre_campo])) {
                     $datos_envio[$control['field_title']] = $_POST[$nombre_campo];
                 } else {
                     $datos_envio[$control['field_title']] = '';
                 }
                 continue;
             }

             // For all other input types (text, textarea, number, email, date, time, datetime-local, etc.)
             $valor = isset($_POST[$nombre_campo]) ? $_POST[$nombre_campo] : '';
             $datos_envio[$control['field_title']] = $valor;
         }

         // Capture additional submission details
         $unique_id = uniqid("env_", true);
         $submission_datetime = date("Y-m-d H:i:s");
         $submission_epoch = time();
         $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
         $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';

         // Insert submission in DB including the extra fields
         $stmt = $db->prepare("INSERT INTO submissions (form_id, unique_id, data, datetime, epoch, ip, user_agent) VALUES (:form_id, :unique_id, :data, :datetime, :epoch, :ip, :user_agent)");
         $stmt->bindValue(':form_id', $form['id'], SQLITE3_INTEGER);
         $stmt->bindValue(':unique_id', $unique_id, SQLITE3_TEXT);
         $stmt->bindValue(':data', json_encode($datos_envio), SQLITE3_TEXT);
         $stmt->bindValue(':datetime', $submission_datetime, SQLITE3_TEXT);
         $stmt->bindValue(':epoch', $submission_epoch, SQLITE3_INTEGER);
         $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
         $stmt->bindValue(':user_agent', $user_agent, SQLITE3_TEXT);
         $stmt->execute();

         echo "<div id='content'><p>Gracias por tu envío. Tu ID de envío es: <strong>" . htmlspecialchars($unique_id) . "</strong></p></div>";
         html_footer();
         exit;
    }

    // Show the form
    echo "<div id='content'>";
    echo "<h2>" . htmlspecialchars($form['title']) . "</h2>";
    echo "<form method='post' id='publicForm' enctype='multipart/form-data'>";

    foreach ($controles as $control) {
         echo "<div class='form-field'>";
         // Label
         echo "<label>" . htmlspecialchars($control['field_title']);
         echo ($control['required'] ? " *" : "") . ":</label><br>";

         // Description
         if (!empty($control['description'])) {
             echo "<small>" . htmlspecialchars($control['description']) . "</small><br>";
         }

         // Common attributes
         $nombre_campo = "campo_" . $control['id'];
         $atributos = "";
         if (!empty($control['min_length'])) {
             $atributos .= " minlength='" . intval($control['min_length']) . "'";
         }
         if (!empty($control['max_length'])) {
             $atributos .= " maxlength='" . intval($control['max_length']) . "'";
         }
         if (!empty($control['placeholder'])) {
             $atributos .= " placeholder='" . htmlspecialchars($control['placeholder']) . "'";
         }
         if ($control['required']) {
             $atributos .= " required";
         }

         // Render the input according to its type
         switch ($control['type']) {
             case 'none':
                 // No input, just show label/description
                 break;

             case 'textarea':
                 echo "<textarea name='" . htmlspecialchars($nombre_campo) . "' rows='4' {$atributos}></textarea>";
                 break;

             case 'checkbox':
                 $options = array_map('trim', explode(',', $control['field_values']));
                 foreach ($options as $opt) {
                     $optSafe = htmlspecialchars($opt);
                     echo "<label><input type='checkbox' name='" . htmlspecialchars($nombre_campo) . "[]' value='{$optSafe}'> {$optSafe}</label><br>";
                 }
                 break;

             case 'radio':
                 $options = array_map('trim', explode(',', $control['field_values']));
                 foreach ($options as $opt) {
                     $optSafe = htmlspecialchars($opt);
                     echo "<label><input type='radio' name='" . htmlspecialchars($nombre_campo) . "' value='{$optSafe}' {$atributos}> {$optSafe}</label><br>";
                 }
                 break;

             case 'select':
                 echo "<select name='" . htmlspecialchars($nombre_campo) . "' {$atributos}>";
                 $options = array_map('trim', explode(',', $control['field_values']));
                 foreach ($options as $opt) {
                     $optSafe = htmlspecialchars($opt);
                     echo "<option value='{$optSafe}'>{$optSafe}</option>";
                 }
                 echo "</select>";
                 break;

             case 'file':
                 echo "<input type='file' name='" . htmlspecialchars($nombre_campo) . "' {$atributos} />";
                 break;

             case 'time':
                 echo "<input type='time' name='" . htmlspecialchars($nombre_campo) . "' {$atributos} />";
                 break;

             case 'date':
                 echo "<input type='date' name='" . htmlspecialchars($nombre_campo) . "' {$atributos} />";
                 break;

             case 'datetime':
             case 'datetime-local':
                 echo "<input type='datetime-local' name='" . htmlspecialchars($nombre_campo) . "' {$atributos} />";
                 break;

             default:
                 $type = htmlspecialchars($control['type']);
                 echo "<input type='{$type}' name='" . htmlspecialchars($nombre_campo) . "' {$atributos} />";
                 break;
         }

         echo "</div>";
    }

    echo "<button type='submit'>Enviar</button>";
    echo "</form>";
    echo "</div>";
    html_footer();
}

// ---------------------
// Admin Area Handler
// ---------------------
function manejar_admin() {
    global $db;
    $accion = $_GET['admin'];

    // Admin login
    if ($accion == 'login') {
         html_header("Acceso Administrador - " . APP_NAME);
         echo "<div id='content'>";
         if ($_SERVER['REQUEST_METHOD'] == 'POST') {
              $usuario = $_POST['username'];
              $clave = $_POST['password'];

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
         echo "<form method='post' id='loginForm'>";
         echo "<label>Usuario:</label> <input type='text' name='username' required><br><br>";
         echo "<label>Contraseña:</label> <input type='password' name='password' required><br><br>";
         echo "<button type='submit'>Iniciar Sesión</button>";
         echo "</form>";
         echo "</div>";
         html_footer();
         exit;
    }

    // Logout
    if ($accion == 'logout') {
         session_destroy();
         header("Location: ?admin=login");
         exit;
    }

    // All other admin actions require login
    requiere_login();

    if ($accion == 'dashboard') {
         admin_dashboard();
         exit;
    } elseif ($accion == 'newform') {
         admin_new_form();
         exit;
    } elseif ($accion == 'editform') {
         if (!isset($_GET['id'])) {
             echo "ID del formulario no especificado.";
             exit;
         }
         $form_id = intval($_GET['id']);
         admin_edit_form($form_id);
         exit;
    } elseif ($accion == 'viewsubmissions') {
         if (!isset($_GET['id'])) {
             echo "ID del formulario no especificado.";
             exit;
         }
         $form_id = intval($_GET['id']);
         admin_view_submissions($form_id);
         exit;
    } else {
         echo "Acción administrativa desconocida.";
         exit;
    }
}

function admin_dashboard() {
    global $db;
    html_header("Panel de Control - " . APP_NAME);
    admin_menu();
    echo "<div id='content'>";
    $resultado = $db->query("SELECT * FROM forms ORDER BY id DESC");
    echo "<h2>Tus Formularios</h2>";
    echo "<table>
            <tr>
              <th>ID</th>
              <th>Título</th>
              <th>Hash</th>
              <th>Acciones</th>
            </tr>";
    while ($row = $resultado->fetchArray(SQLITE3_ASSOC)) {
         echo "<tr>";
         echo "<td>" . $row['id'] . "</td>";
         echo "<td>" . htmlspecialchars($row['title']) . "</td>";
         echo "<td>" . htmlspecialchars($row['hash']) . "</td>";
         echo "<td>
                 <a href='?admin=editform&id=" . $row['id'] . "'>Editar</a> | 
                 <a href='?admin=viewsubmissions&id=" . $row['id'] . "'>Ver Envíos</a> | 
                 <a href='?form=" . htmlspecialchars($row['hash']) . "' target='_blank'>Ver Formulario</a>
               </td>";
         echo "</tr>";
    }
    echo "</table>";
    echo "</div>";
    html_footer();
}

function admin_new_form() {
    global $db;
    html_header("Crear Nuevo Formulario - " . APP_NAME);
    admin_menu();
    echo "<div id='content'>";
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
         $titulo = $_POST['title'];
         $stmt = $db->prepare("INSERT INTO forms (title, hash) VALUES (:title, '')");
         $stmt->bindValue(':title', $titulo, SQLITE3_TEXT);
         $stmt->execute();
         $form_id = $db->lastInsertRowID();

         // Generate a hash based on form_id, time, random
         $hash = md5($form_id . time() . rand());
         $stmt = $db->prepare("UPDATE forms SET hash = :hash WHERE id = :id");
         $stmt->bindValue(':hash', $hash, SQLITE3_TEXT);
         $stmt->bindValue(':id', $form_id, SQLITE3_INTEGER);
         $stmt->execute();

         header("Location: ?admin=editform&id=" . $form_id);
         exit;
    }
    echo "<form method='post' id='newForm'>";
    echo "<label>Título del Formulario:</label> <input type='text' name='title' required><br><br>";
    echo "<button type='submit'>Crear Formulario</button>";
    echo "</form>";
    echo "<p><a href='?admin=dashboard'>Volver al Panel de Control</a></p>";
    echo "</div>";
    html_footer();
}

function admin_edit_form($form_id) {
    global $db;
    // Get the form
    $stmt = $db->prepare("SELECT * FROM forms WHERE id = :id");
    $stmt->bindValue(':id', $form_id, SQLITE3_INTEGER);
    $form = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if (!$form) {
         echo "Formulario no encontrado.";
         exit;
    }

    html_header("Editar Formulario: " . $form['title'] . " - " . APP_NAME);
    admin_menu();
    echo "<div id='content'>";
    echo "<p class='url'>URL del Formulario Externo: <a href='?form=" . htmlspecialchars($form['hash']) . "' target='_blank'>?form=" . htmlspecialchars($form['hash']) . "</a></p>";

    // Process new field
    if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['field_title'])) {
         $field_title = $_POST['field_title'];
         $description = isset($_POST['description']) ? $_POST['description'] : '';
         $placeholder = isset($_POST['placeholder']) ? $_POST['placeholder'] : '';
         $required = isset($_POST['required']) ? 1 : 0;
         $type = $_POST['type'];
         $min_length = !empty($_POST['min_length']) ? intval($_POST['min_length']) : null;
         $max_length = !empty($_POST['max_length']) ? intval($_POST['max_length']) : null;
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

    // New field form
    echo "<h2>Agregar Nuevo Campo</h2>";
    echo "<form method='post' id='newControl'>";
    echo "<label>Título del Campo:</label> <input type='text' name='field_title' required><br><br>";
    echo "<label>Descripción (opcional):</label><br> <textarea name='description'></textarea><br><br>";
    echo "<label>Placeholder (opcional):</label><br> <input type='text' name='placeholder'><br><br>";
    echo "<label>Obligatorio:</label> <input type='checkbox' name='required' value='1'><br><br>";
    echo "<label>Tipo:</label> 
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
            <option value='select'>Select (desplegable)</option>
            <option value='file'>Archivo</option>
          </select><br><br>";
    echo "<label>Valores (para checkbox, radio o select - separar por comas):</label><br> 
          <input type='text' name='values'><br><br>";
    echo "<label>Longitud Mínima (opcional):</label> <input type='number' name='min_length' min='0'><br><br>";
    echo "<label>Longitud Máxima (opcional):</label> <input type='number' name='max_length' min='0'><br><br>";
    echo "<button type='submit'>Agregar Campo</button>";
    echo "</form>";

    // List current fields
    echo "<h2>Campos Actuales</h2>";
    $stmt = $db->prepare("SELECT * FROM controls WHERE form_id = :form_id");
    $stmt->bindValue(':form_id', $form_id, SQLITE3_INTEGER);
    $resultado = $stmt->execute();
    if ($resultado) {
        echo "<ul class='control-list'>";
        while ($row = $resultado->fetchArray(SQLITE3_ASSOC)) {
             echo "<li>";
             echo "<strong>" . htmlspecialchars($row['field_title']) . "</strong> ";
             echo "(" . htmlspecialchars($row['type']) . ")";
             if (!empty($row['description'])) {
                echo " - <em>" . htmlspecialchars($row['description']) . "</em>";
             }
             if (!empty($row['placeholder'])) {
                echo " [Placeholder: " . htmlspecialchars($row['placeholder']) . "]";
             }
             if ($row['required']) {
                echo " <strong>(Obligatorio)</strong>";
             }
             if (!empty($row['min_length'])) {
                echo " [Min: " . $row['min_length'] . "]";
             }
             if (!empty($row['max_length'])) {
                echo " [Max: " . $row['max_length'] . "]";
             }
             if (!empty($row['field_values'])) {
                echo " [Valores: " . htmlspecialchars($row['field_values']) . "]";
             }
             echo "</li>";
        }
        echo "</ul>";
    }
    echo "</div>";
    html_footer();
}

function admin_view_submissions($form_id) {
    global $db;
    $stmt = $db->prepare("SELECT * FROM forms WHERE id = :id");
    $stmt->bindValue(':id', $form_id, SQLITE3_INTEGER);
    $form = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if (!$form) {
         echo "Formulario no encontrado.";
         exit;
    }
    html_header("Envíos para " . $form['title'] . " - " . APP_NAME);
    admin_menu();
    echo "<div id='content'>";
    // Updated table header to show extra fields
    echo "<h2>Envíos</h2>";
    echo "<table>
            <tr>
              <th>ID</th>
              <th>ID de Envío</th>
              <th>Datos</th>
              <th>Fecha y Hora</th>
              <th>Epoch</th>
              <th>IP</th>
              <th>User Agent</th>
            </tr>";
    while ($row = $db->query("SELECT * FROM submissions WHERE form_id = " . intval($form_id) . " ORDER BY id DESC")->fetchArray(SQLITE3_ASSOC)) {
         echo "<tr>";
         echo "<td>" . $row['id'] . "</td>";
         echo "<td>" . htmlspecialchars($row['unique_id']) . "</td>";
         echo "<td>";
         $data = json_decode($row['data'], true);
         if (is_array($data)) {
             foreach ($data as $label => $value) {
                 // If it's a file path, show a link
                 if (strpos($value, 'media/') === 0) {
                     $filename = basename($value);
                     echo "<strong>" . htmlspecialchars($label) . ":</strong> 
                           <a href='" . htmlspecialchars($value) . "' target='_blank'>" . htmlspecialchars($filename) . "</a><br>";
                 } else {
                     echo "<strong>" . htmlspecialchars($label) . ":</strong> " . htmlspecialchars($value) . "<br>";
                 }
             }
         } else {
             echo htmlspecialchars($row['data']);
         }
         echo "</td>";
         echo "<td>" . htmlspecialchars($row['datetime']) . "</td>";
         echo "<td>" . htmlspecialchars($row['epoch']) . "</td>";
         echo "<td>" . htmlspecialchars($row['ip']) . "</td>";
         echo "<td>" . htmlspecialchars($row['user_agent']) . "</td>";
         echo "</tr>";
    }
    echo "</table>";
    echo "</div>";
    html_footer();
}
?>

