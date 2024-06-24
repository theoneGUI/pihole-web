<?php
session_start();
require_once 'icls.php';

if (icls_federated_session(icls_sessvar())) {
    header("Location: /");
    die("already logged in");
}
else {
    if (icls_federated_session(icls_post())) {
        $_SESSION["ICLS_Int_Sess"] = icls_post();
        $_SESSION['auth'] = true;
    }
    else {
        die('no, no.');
    }
}

?>