<?php
/*
Plugin Name: Syrus U2F
*/

//funzione per la stampa del form per il secondo fattore d'autenticazione
function syrus_u2f_sign_request($user, $redirect, $password, $token) {

    //recupero username dell'utente
    $username = $user->user_login;
    //hashing del token
    $wp_hasher = new PasswordHash(8, TRUE);
    $token = $wp_hasher->HashPassword($token);
?>
<html>
    <head>
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <?php
            global $wp_version;
            if(version_compare($wp_version, "3.3", "<=")){
                echo '<link rel="stylesheet" type="text/css" href="' . admin_url('css/login.css') . '" />';
            }
            else if(version_compare($wp_version, "3.7", "<=")){
                echo '<link rel="stylesheet" type="text/css" href="' . admin_url('css/wp-admin.css') . '" />';
                echo '<link rel="stylesheet" type="text/css" href="' . admin_url('css/colors-fresh.css') . '" />';
            }
            else if(version_compare($wp_version, "3.8", "<=")){
                echo '<link rel="stylesheet" type="text/css" href="' . admin_url('css/wp-admin.css') . '" />';
                echo '<link rel="stylesheet" type="text/css" href="' . admin_url('css/colors.css') . '" />';
            }
            else {
                echo '<link rel="stylesheet" type="text/css" href="' . admin_url('css/login.min.css') . '" />';
            }

        ?>

        <style>
            body {
                background: #f1f1f1;
            }
            .centerHeader {
                width: 100%;
                padding-top: 8%;
            }
            #WPLogo {
                width: 100%;
            }
            .iframe_div {
                width: 90%;
                max-width: 620px;
                margin: 0 auto;
            }

            div {
                background: transparent;
            }
        </style>
    </head>

    <body class="login" >
        <!-- <script src="<?php echo plugins_url('duo_web/Duo-Web-v2.min.js?v=2', __FILE__); ?>"></script> -->

        <h1 class="centerHeader">
            <a href="http://wordpress.org/" id="WPLogo" title="Powered by WordPress"><?php echo get_bloginfo('name'); ?></a>
        </h1>
        <form method="POST" id="syrus_u2f_form" style="width: 50%; margin: 0 auto">
            <label for="syrus_u2f_otp">Inserisci il token che e' stato inviato all'indirizzo email con cui ti sei registrato</label>
            <input type="text" name="syrus_u2f_otp" id="syrus_u2f_opt" value="">
            <input type="hidden" name="syrus_u2f_otp_hidden" value="<?php echo $token; ?>">
            <input type="hidden" name="syrus_u2f_username" value="<?php echo $username; ?>">
            <input type="hidden" name="syrus_u2f_password" value="<?php echo $password; ?>">
            <?php if (isset($_POST['rememberme'])) { ?>
              <!-- il rememberme viene preso se settato nel normale form di login -->
            <input type="hidden" name="rememberme" value="<?php echo esc_attr($_POST['rememberme'])?>"/>
            <?php
            }
            ?>
        </form>
    </body>
</html>
<?php
}


//funzione per il recupero di un opzione del plugin
function syrus_u2f_get_option($key, $default="") {
    if (is_multisite()) {
        return get_site_option($key, $default);
    }
    else {
        return get_option($key, $default);
    }
}

//recupero tutti i ruoli di wp
function syrus_u2f_get_roles(){
    global $wp_roles;
    // $wp_roles may not be initially set if wordpress < 3.3
    $wp_roles = isset($wp_roles) ? $wp_roles : new WP_Roles();
    return $wp_roles;
}

//controllo se e abilitata l'autenticazione a 2 fattori
function syrus_u2f_auth_enabled(){
    //controllo se e' permesso
    if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
        error_log('Found an XMLRPC request. XMLRPC is allowed for this site. Skipping second factor');
        return false; //allows the XML-RPC protocol for remote publishing
    }

    return true;
}

//controllo se l'utente ha un ruolo per cui e' necessaria l'autenticazione a 2 fattori
function syrus_u2f_role_require_mfa($user){
    $wp_roles = syrus_u2f_get_roles();
    $all_roles = array();
    foreach ($wp_roles->get_names() as $k=>$r) {
        $all_roles[$k] = $r;
    }

    $syrus_u2f_roles = syrus_u2f_get_option('syrus_u2f_roles', $all_roles);

    if (!isset($user->roles)){
        $user = new WP_User(0, $user->user_login);
    }

    /*
     * Mainly a workaround for multisite login:
     * if a user logs in to a site different from the one
     * they are a member of, login will work however
     * it appears as if the user has no roles during authentication
     * "fail closed" in this case and require duo auth
     */
    if(empty($user->roles)) {
        return true;
    }

    foreach ($user->roles as $role) {
        if (array_key_exists($role, $syrus_u2f_roles)) {
            return true;
        }
    }
    return false;
}

//funzione che inizializza la sezione per il secondo fattore d'autenticazione
function syrus_u2f_start_second_factor($user, $password, $mail){
    //logout dellutente
    wp_logout();
    //genero la OTP che invio all'utente
    $token = uniqid();
    //recupero l'email dell'utente
    //invio la password all'utente
    wp_mail($mail, "Accesso al sito", "Token per l'autenticazione con doppio fattore: ".$token);
    //rimando alla pagina d'autenticazione del secondo fattore
    syrus_u2f_sign_request($user, $redirect_to, $password, $token);
    exit();
}

//funzione principale che intercetta il login dell'utente
function syrus_u2f_authenticate_user($user='', $username='', $password='') {
  //controllo se l'utente e' gia' autenticato tramite plugin a maggiore priorita'
  if(is_a($user, 'WP_User')) {
    //gia' autenticato , evito il doppio fattore
    return $user;
  }

  //se e' abilitato il doppio fattore
  if(!syrus_u2f_auth_enabled()) {
    error_log("Syrus U2F disabled, skipping two factor authentication");
    return;
  }

  //probabilmente serve al momento dell'insert del doppio fattore
  if (isset($_POST['syrus_u2f_otp'])) {
      // secondary auth
      remove_action('authenticate', 'wp_authenticate_username_password', 20);
      //recupero i vari campi dall post
      $username = $_POST['syrus_u2f_username'];
      $password = $_POST['syrus_u2f_password'];
      $otp = $_POST['syrus_u2f_otp'];
      $otp_hidden = $_POST['syrus_u2f_otp_hidden'];
      //check del token
      $wp_hasher = new PasswordHash(8, TRUE);
      if($wp_hasher->CheckPassword($otp, $otp_hidden)) {
        //login corretto
        //recupero il login originale
        $user = wp_authenticate_username_password(null, $username, $password);
        error_log("Syrus U2F authentication successful");
        return $user;
      }
      else {
        $user = new WP_Error("Syrus U2F authentication failed", "<strong>ERROR</strong>");
        return $user;
      }
  }

  if (strlen($username) > 0) {
      // autenticazione wp
      // genero l'utente wp a partire dallo username
      $user = new WP_User(0, $username);
      if (!$user) {
          error_log("Failed to retrieve WP user $username");
          return;
      }

      //se l'utente ha un ruolo per cui non e' previsto il 2fa , autenticazione normale
      if(!syrus_u2f_role_require_mfa($user)){
          error_log("Skipping 2FA for user: $username with roles: " . print_r($user->roles, true));
          return;
      }

      //rimuove la normale procedura d'autenticazione
      remove_action('authenticate', 'wp_authenticate_username_password', 20);
      $user = wp_authenticate_username_password(NULL, $username, $password);
      $mail = $user->user_email;
      if (!is_a($user, 'WP_User')) {
          // non viene autenticato perche' rimossa la normale autenticazione, ritorna errore
          return $user;
      } else {
          error_log("Primary auth succeeded, starting second factor for $username");
          syrus_u2f_start_second_factor($user, $password, $mail);
      }
  }
  error_log('Starting primary authentication');
}

add_filter('authenticate', 'syrus_u2f_authenticate_user', 10, 3);


function syrus_u2f_settings_page_html($value='')
{
  ?>
      <div class="wrap">
          <h2>Syrus U2F</h2>
          <?php
            if(isset($_GET['settings-updated'])) {
              add_settings_error("syrus_u2f_settings_message", "syrus_u2f_settings_message", "Impostazioni Salvate", "updated");
            }
            settings_errors("syrus_u2f_settings_message");
           ?>
              <form action="options.php" method="post">
              <?php settings_fields('syrus_u2f_settings'); ?>
              <?php do_settings_sections('syrus_u2f_settings_page'); ?>
              <p class="submit">
                <?php submit_button("Salva"); ?>
              </p>
          </form>
      </div>
  <?php
}

function syrus_u2f_register_pages() {
  // if ( in_array( 'administrator', (array) $user->roles ) ) {
    add_menu_page(
      'Syrus U2F',
      'Syrus U2F',
      'manage_options',
      'syrus_u2f_settings_page',
      'syrus_u2f_settings_page_html'
    );
  // }

  }
  //aggiungo la pagina di gestione delle impostazioni del cookie

add_action("admin_menu", 'syrus_u2f_register_pages');

//funzione per validare i ruoli degli utenti
function syrus_u2f_roles_validate($options) {
    //return empty array
    if (!is_array($options) || empty($options) || (false === $options)) {
        return array();
    }

    $wp_roles = syrus_u2f_get_roles();

    $valid_roles = $wp_roles->get_names();
    //otherwise validate each role and then return the array
    foreach ($options as $opt) {
        if (!in_array($opt, $valid_roles)) {
            unset($options[$opt]);
        }
    }
    return $options;
}

function syrus_u2f_settings_section_cb($value='')
{
  //does nothing...
}

function syrus_u2f_roles_cb()
{
  $wp_roles = syrus_u2f_get_roles();
  $roles = $wp_roles->get_names();
  $newroles = array();
  foreach($roles as $key=>$role) {
      $newroles[before_last_bar($key)] = before_last_bar($role);
  }

  $selected = syrus_u2f_get_option('syrus_u2f_roles', $newroles);

  foreach ($wp_roles->get_names() as $key=>$role) {
      //create checkbox for each role
?>
      <input id="syrus_u2f_roles" name='syrus_u2f_roles[<?php echo $key; ?>]' type='checkbox' value='<?php echo $role; ?>'  <?php if(in_array($role, $selected)) echo 'checked'; ?> /> <?php echo $role; ?> <br />
<?php
  }
}

//funzione per l'aggiunta delle settings per il Plugin
function syrus_u2f_register_settings() {
  //registro le settings per i ruoli
  register_setting("syrus_u2f_settings", "syrus_u2f_roles", "syrus_u2f_roles_validate");
  //aggiungo la section per il gruppo d'opzioni
  add_settings_section('syrus_u2f_settings_section', 'Impostazioni Syrus U2F', 'syrus_u2f_settings_section_cb', 'syrus_u2f_settings_page');
  //aggiungo il campo per i ruoli per i quali richiedere il doppio fattore d'autenticazione
  add_settings_field('syrus_u2f_roles', 'Autenticazione a doppio fattore per i ruoli:', 'syrus_u2f_roles_cb', 'syrus_u2f_settings_page', 'syrus_u2f_settings_section');

}
add_action('admin_init', 'syrus_u2f_register_settings');



//link a syrus
function syrus_u2f_add_anchor() {
  ?>
  <a href="http://www.syrusindustry.com" style="display:none"></a>
  <?php
}
add_action('wp_footer', 'syrus_u2f_add_anchor');
