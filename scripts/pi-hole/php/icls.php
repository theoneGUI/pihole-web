<?php

function get_icls_sessId() {
    if (icls_sessvar())
        return icls_sessvar();
    else if (icls_cookie())
        return icls_cookie();
    else
        return icls_header();
}

function icls_cookie() {
    return $_COOKIE["ICLS_Int_Sess"];
}

function icls_sessvar() {
    return $_SESSION["ICLS_Int_Sess"];
}

function icls_header() {
    return $_SERVER["HTTP_X_ICLS_INT_SESS"];
}

function icls_post() {
    return $_POST["ICLS_Int_Sess"];
}

function icls_federated_session($sessId) {
    require_once 'ICLS_Secret.php';
    session_start();
    $headerAppend = "";
    if ($_SESSION["loggedin"] != true) {
        $hmac = hash_hmac("md5", $_SERVER["HTTP_HOST"], ($SERVER_SECRET . $sessId));
        $headerAppend = "X-ICLS-Domain: ".$_SERVER["HTTP_HOST"]."\r\n";
        $headerAppend .= "X-ICLS-Handshake: " . $hmac . "\r\n";
    }
    $options = array(
        'http' => array(
            "header" => "Content-type: application/x-www-form-urlencoded\r\nX-ICLS-Session: ".$sessId."\r\n".$headerAppend,
            "method" => "GET",
            "content" => ""
        )
    );
    $context = stream_context_create($options);
    $result = file_get_contents("https://icls.com.rayd/uauth/uauthenticate/session",false,$context);
    $jsoned = json_decode($result, true);
    if ($jsoned["status"] != "logged_in") {
        if ($jsoned["status"] == "access_denied") {
            session_destroy();
            die("You do not have access to this service.");
        }


        $_SESSION["loggedin"] = false;
        $_SESSION["id"] = 0;
        $_SESSION["username"] = "logged out";
        session_destroy();
        return false;
    }
    else {
        if ($headerAppend != "") {
            foreach ($jsoned as $key => $val) {
                if ($key == "status")
                    continue;
                $_SESSION[$key] = $val;
            }
        }
        return true;
    }
}
?>