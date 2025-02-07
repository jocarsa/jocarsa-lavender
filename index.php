<?php
session_start();

define('APP_NAME', 'jocarsa | Lavanda');

// Abrir (o crear) la base de datos SQLite en el mismo directorio
$db = new SQLite3('db.sqlite');

// Inicializar la base de datos (crear tablas si es necesario y agregar el usuario por defecto)
inicializar_db($db);

function inicializar_db($db) {
    // Tabla de usuarios
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )");
    // Crear usuario administrador por defecto si no existe
    $stmt = $db->prepare("SELECT COUNT(*) as count FROM users WHERE username = :username");
    $stmt->bindValue(':username', 'jocarsa', SQLITE3_TEXT);
    $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if ($result['count'] == 0) {
        $db->exec("INSERT INTO users (username, password) VALUES ('jocarsa', 'jocarsa')");
    }

    // Tabla de formularios
    $db->exec("CREATE TABLE IF NOT EXISTS forms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        hash TEXT UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    // Tabla de controles (campos) con nuevos parámetros:
    // field_title, description, placeholder, type, min_length, max_length y required (0 o 1)
    $db->exec("CREATE TABLE IF NOT EXISTS controls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        form_id INTEGER,
        field_title TEXT,
        description TEXT,
        placeholder TEXT,
        type TEXT,
        min_length INTEGER,
        max_length INTEGER,
        required INTEGER DEFAULT 0
    )");

    // Tabla de envíos (se almacenan los datos en JSON)
    $db->exec("CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        form_id INTEGER,
        unique_id TEXT,
        data TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
}

// ---------------------
// Funciones de ayuda
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
</head>
<body>
<div id='wrapper'>
  <header id='header'>
    <h1>" . APP_NAME . "</h1>
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
// Enrutamiento
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
// Manejador del Formulario Público
// ---------------------
function manejar_formulario_publico($hash) {
    global $db;
    html_header("Completar Formulario - " . APP_NAME);
    // Buscar el formulario por hash único
    $stmt = $db->prepare("SELECT * FROM forms WHERE hash = :hash");
    $stmt->bindValue(':hash', $hash, SQLITE3_TEXT);
    $form = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if (!$form) {
        echo "<div id='content'><p>Formulario no encontrado.</p></div>";
        html_footer();
        exit;
    }
    // Recuperar todos los controles (campos) para este formulario
    $stmt = $db->prepare("SELECT * FROM controls WHERE form_id = :form_id");
    $stmt->bindValue(':form_id', $form['id'], SQLITE3_INTEGER);
    $resultado = $stmt->execute();
    $controles = [];
    while ($row = $resultado->fetchArray(SQLITE3_ASSOC)) {
         $controles[] = $row;
    }
    // Procesar envío
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
         $datos_envio = [];
         foreach ($controles as $control) {
             $nombre_campo = "campo_" . $control['id'];
             $datos_envio[$control['field_title']] = isset($_POST[$nombre_campo]) ? $_POST[$nombre_campo] : '';
         }
         $unique_id = uniqid("env_", true);
         $stmt = $db->prepare("INSERT INTO submissions (form_id, unique_id, data) VALUES (:form_id, :unique_id, :data)");
         $stmt->bindValue(':form_id', $form['id'], SQLITE3_INTEGER);
         $stmt->bindValue(':unique_id', $unique_id, SQLITE3_TEXT);
         $stmt->bindValue(':data', json_encode($datos_envio), SQLITE3_TEXT);
         $stmt->execute();
         echo "<div id='content'><p>Gracias por tu envío. Tu ID de envío es: <strong>" . htmlspecialchars($unique_id) . "</strong></p></div>";
         html_footer();
         exit;
    }
    // Mostrar el formulario
    echo "<div id='content'>";
    echo "<h2>" . htmlspecialchars($form['title']) . "</h2>";
    echo "<form method='post' id='publicForm'>";
    foreach ($controles as $control) {
         echo "<div class='form-field'>";
         echo "<label>" . htmlspecialchars($control['field_title']) . ($control['required'] ? " *" : "") . ":</label><br>";
         if (!empty($control['description'])) {
             echo "<small>" . htmlspecialchars($control['description']) . "</small><br>";
         }
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
         if ($control['type'] == 'textarea') {
             echo "<textarea name='" . htmlspecialchars($nombre_campo) . "' rows='4' {$atributos}></textarea>";
         } else {
             echo "<input type='" . htmlspecialchars($control['type']) . "' name='" . htmlspecialchars($nombre_campo) . "' {$atributos} />";
         }
         echo "</div>";
    }
    echo "<button type='submit'>Enviar</button>";
    echo "</form>";
    echo "</div>";
    html_footer();
}

// ---------------------
// Manejador del Área de Administración
// ---------------------
function manejar_admin() {
    global $db;
    $accion = $_GET['admin'];
    // Página de acceso de administrador
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
    // Cerrar sesión
    if ($accion == 'logout') {
         session_destroy();
         header("Location: ?admin=login");
         exit;
    }
    // Todas las páginas administrativas siguientes requieren login
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
    echo "<p>URL del Formulario Externo: <a href='?form=" . htmlspecialchars($form['hash']) . "' target='_blank'>?form=" . htmlspecialchars($form['hash']) . "</a></p>";
    
    // Procesar el alta de un nuevo campo
    if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['field_title'])) {
         $field_title = $_POST['field_title'];
         $description = isset($_POST['description']) ? $_POST['description'] : '';
         $placeholder = isset($_POST['placeholder']) ? $_POST['placeholder'] : '';
         $required = isset($_POST['required']) ? 1 : 0;
         $type = $_POST['type'];
         $min_length = !empty($_POST['min_length']) ? intval($_POST['min_length']) : null;
         $max_length = !empty($_POST['max_length']) ? intval($_POST['max_length']) : null;
         $stmt = $db->prepare("INSERT INTO controls (form_id, field_title, description, placeholder, type, min_length, max_length, required) VALUES (:form_id, :field_title, :description, :placeholder, :type, :min_length, :max_length, :required)");
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
         $stmt->execute();
         header("Location: ?admin=editform&id=" . $form_id);
         exit;
    }
    // Formulario para agregar un nuevo campo
    echo "<h2>Agregar Nuevo Campo</h2>";
    echo "<form method='post' id='newControl'>";
    echo "<label>Título del Campo:</label> <input type='text' name='field_title' required><br><br>";
    echo "<label>Descripción (opcional):</label> <textarea name='description'></textarea><br><br>";
    echo "<label>Placeholder (opcional):</label> <input type='text' name='placeholder'><br><br>";
    echo "<label>Obligatorio:</label> <input type='checkbox' name='required' value='1'><br><br>";
    echo "<label>Tipo:</label> 
          <select name='type'>
            <option value='text'>Texto</option>
            <option value='textarea'>Área de Texto</option>
            <option value='number'>Número</option>
            <option value='email'>Correo</option>
            <option value='date'>Fecha</option>
            <option value='password'>Contraseña</option>
            <option value='url'>URL</option>
          </select><br><br>";
    echo "<label>Longitud Mínima (opcional):</label> <input type='number' name='min_length' min='0'><br><br>";
    echo "<label>Longitud Máxima (opcional):</label> <input type='number' name='max_length' min='0'><br><br>";
    echo "<button type='submit'>Agregar Campo</button>";
    echo "</form>";
    
    // Listar los campos actuales
    echo "<h2>Campos Actuales</h2>";
    $stmt = $db->prepare("SELECT * FROM controls WHERE form_id = :form_id");
    $stmt->bindValue(':form_id', $form_id, SQLITE3_INTEGER);
    $resultado = $stmt->execute();
    if ($resultado) {
        echo "<ul class='control-list'>";
        while ($row = $resultado->fetchArray(SQLITE3_ASSOC)) {
             echo "<li>" . htmlspecialchars($row['field_title']) . " (" . htmlspecialchars($row['type']) . ")";
             if (!empty($row['description'])) {
                echo " - " . htmlspecialchars($row['description']);
             }
             if (!empty($row['placeholder'])) {
                echo " [Placeholder: " . htmlspecialchars($row['placeholder']) . "]";
             }
             if ($row['required']) {
                echo " <strong>* Obligatorio</strong>";
             }
             if (!empty($row['min_length'])) {
                echo " [Min: " . $row['min_length'] . "]";
             }
             if (!empty($row['max_length'])) {
                echo " [Max: " . $row['max_length'] . "]";
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
    $stmt = $db->prepare("SELECT * FROM submissions WHERE form_id = :form_id ORDER BY id DESC");
    $stmt->bindValue(':form_id', $form_id, SQLITE3_INTEGER);
    $resultado = $stmt->execute();
    echo "<h2>Envíos</h2>";
    echo "<table>
            <tr>
              <th>ID</th>
              <th>ID de Envío</th>
              <th>Datos</th>
              <th>Enviado el</th>
            </tr>";
    while ($row = $resultado->fetchArray(SQLITE3_ASSOC)) {
         echo "<tr>";
         echo "<td>" . $row['id'] . "</td>";
         echo "<td>" . htmlspecialchars($row['unique_id']) . "</td>";
         $data = json_decode($row['data'], true);
         echo "<td>";
         if (is_array($data)) {
             foreach ($data as $label => $value) {
                 echo "<strong>" . htmlspecialchars($label) . ":</strong> " . htmlspecialchars($value) . "<br>";
             }
         } else {
             echo htmlspecialchars($row['data']);
         }
         echo "</td>";
         echo "<td>" . $row['created_at'] . "</td>";
         echo "</tr>";
    }
    echo "</table>";
    echo "</div>";
    html_footer();
}
?>

