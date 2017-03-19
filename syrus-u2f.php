<?php
/*
Plugin Name: Syrus U2F
*/

//funzione per la stampa del form per il secondo fattore d'autenticazione
function syrus_u2f_sign_request($user, $redirect, $password, $token) {
    // $ikey = duo_get_option('duo_ikey');
    // $skey = duo_get_option('duo_skey');
    // $host = duo_get_option('duo_host');
    // $akey = duo_get_akey();

    //recupero username dell'utente
    $username = $user->user_login;
    // $duo_time = duo_get_time();

    // $request_sig = Duo::signRequest($ikey, $skey, $akey, $username, $duo_time);
    // duo_debug_log("Displaying iFrame. Username: $username cookie domain: " . COOKIE_DOMAIN . " redirect_to_url: $redirect ikey: $ikey host: $host duo_time: $duo_time");
    // duo_debug_log("Duo request signature: $request_sig");

    // $post_action = esc_url(site_url('wp-login.php', 'login_post'));
    // $iframe_attributes = array(
        // 'id' => 'syrus_u2f_iframe',
        // 'data-host' => $host,
        // 'data-sig-request' => $request_sig,
        // 'data-post-action' => $post_action,
        // 'frameborder' => '0',
    // );
    // $iframe_attributes = array_map(
        // "parameterize",
        // array_keys($iframe_attributes),
        // array_values($iframe_attributes)
    // );
    // $iframe_attributes = implode(" ", $iframe_attributes);

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
            #duo_iframe {
                height: 330px;
                width: 100%;
                min-width: 304px;
                max-width: 620px;
            }
            div {
                background: transparent;
            }
        </style>
    </head>

    <body class="login" >
        <script src="<?php echo plugins_url('duo_web/Duo-Web-v2.min.js?v=2', __FILE__); ?>"></script>

        <h1 class="centerHeader">
            <a href="http://wordpress.org/" id="WPLogo" title="Powered by WordPress"><?php echo get_bloginfo('name'); ?></a>
        </h1>
        <form method="POST" id="syrus_u2f_form">
            <label for="syrus_u2f_otp">OTP</label>
            <input type="text" name="syrus_u2f_otp" id="syrus_u2f_opt" value="">
            <input type="hidden" name="syrus_u2f_otp_hidden" value="<?php echo $token; ?>">
            <input type="hidden" name="syrus_u2f_username" value="<?php echo $username; ?>">
            <input type="hidden" name="syrus_u2f_password" value="<?php echo $password; ?>">
            <?php if (isset($_POST['rememberme'])) { ?>
              <!-- il rememberme viene preso se settato nel normale form di login -->
            <input type="hidden" name="rememberme" value="<?php echo esc_attr($_POST['rememberme'])?>"/>
            <?php
            }
            if (isset($_REQUEST['interim-login'])){
                echo '<input type="hidden" name="interim-login" value="1"/>';
            }
            else {
              //output della pagina di redirect
                echo '<input type="hidden" name="redirect_to" value="' . esc_attr($redirect) . '"/>';
            }
            ?>
            <?php echo submit_button("Invia"); ?>
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

    // $syrus_u2f_roles = syrus_u2f_get_option('duo_roles', $all_roles);
    $syrus_u2f_roles = array();
    /*
     * WordPress < 3.3 does not include the roles by default
     * Create a User object to get roles info
     * Don't use get_user_by()
     */
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
function syrus_u2f_start_second_factor($user, $password, $mail, $redirect_to=NULL){
    if (!$redirect_to){
        // Some custom themes do not provide the redirect_to value
        // Admin page is a good default
        $redirect_to = isset( $_POST['redirect_to'] ) ? $_POST['redirect_to'] : admin_url();
    }
    //logout dellutente
    wp_logout();
    //genero la OTP che invio all'utente
    $token = uniqid();
    //recupero l'email dell'utente
    //invio la password all'utente
    wp_mail($mail, "OTP", $token);
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
  // if(!syrus_u2f_auth_enabled()) {
    // error_log("Syrus U2F disabled, skipping two factor authentication");
    // return;
  // }

  //probabilmente serve al momento dell'insert del doppio fattore
  if (isset($_POST['syrus_u2f_otp'])) {
      // secondary auth
      remove_action('authenticate', 'wp_authenticate_username_password', 20);
      // $akey = duo_get_akey();
      //recupero i vari campi dall post
      $username = $_POST['syrus_u2f_username'];
      $password = $_POST['syrus_u2f_password'];
      $otp = $_POST['syrus_u2f_otp'];
      $otp_hidden = $_POST['syrus_u2f_otp_hidden'];
      if(strcmp($otp, $otp_hidden) == 0) {
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
      // if(!syrus_u2f_role_require_mfa($user)){
          // error_log("Skipping 2FA for user: $username with roles: " . print_r($user->roles, true));
          // return;
      // }

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
