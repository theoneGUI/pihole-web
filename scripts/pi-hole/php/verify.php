<?php
session_start();
require_once 'icls.php';

if ($_SESSION["auth"] || confederated_session($_COOKIE["ICLS_Int_Sess"])) {
    header("Location: /");
    die("already logged in");
}

function connect() {
    $DB_PATH = "../../../db/database.db";
    $tmp = !file_exists($DB_PATH);
    $db = new SQLite3($DB_PATH);
    if ($tmp) {
        $db->exec("CREATE TABLE 'tokens' ('tokenGiven' TEXT NOT NULL, 'collateral' TEXT NOT NULL)");
    }
    return $db;
}

if (isset($_POST["loneLoginToken"]) && !isset($_POST["session"])) {
    $db = connect();
    $stmt = $db->prepare("INSERT INTO tokens (tokenGiven,collateral) VALUES (:llt, :col)");
    $stmt->bindValue(':llt', $_POST["loneLoginToken"], SQLITE3_TEXT);
    $stmt->bindValue(':col', $_POST["collateral"], SQLITE3_TEXT);
    if($result = $stmt->execute()){
        die("success");
    }
    else {
        die("failed");
    }
}

if ($sessVars = json_decode(urldecode($_POST["session"]),true)) {
    $db = connect();

    $sql = "SELECT tokenGiven, collateral FROM tokens WHERE tokenGiven = :tok";
    $stmt = $db->prepare($sql);
    $stmt->bindValue(":tok", $sessVars["loginToken"], SQLITE3_TEXT);
    $result = $stmt->execute();
    if (count($result) != 1) {
        die("request_rejected::invalid_login_token");
    }
    $result = $result->fetchArray(SQLITE3_ASSOC);
    $fetchedToken = $result[0]["tokenGiven"];
    $fetchedCollateral = $result[0]["collateral"];
    
    if ($fetchedToken == $sessVars["loginToken"]) {
        $valid_tokens = array();
        for ($i = 0; $i < 10; $i++) {
            if ($sessVars["loginToken"] == hash("SHA512",($sessVars["id"] . $sessVars["username"] . gmdate("d-m-Y h:i:s", strtotime("-{$i} seconds"))))) {
                foreach ($sessVars as $key => $val) {
                    if ($key == "status")
                        continue;
                    $_SESSION[$key] = $val;
                }
                $_SESSION['auth'] = true;

                $delsql = "DELETE FROM tokens WHERE tokenGiven = :tok";
                $stmt = $db->prepare($delsql);
                $stmt->bindValue(":tok", $fetchedToken, SQLITE3_TEXT);
                $stmt->execute();

                $handshake = hash("SHA256", ($fetchedCollateral . $_SERVER["REMOTE_ADDR"]));
                $options = array(
                        'http' => array(
                        "header" => "Content-type: application/x-www-form-urlencoded\r\nX-ICLS-Session: ".$sessVars["sessionName"]."\r\nX-ICLS-Handshake: ".$handshake."\r\n",
                        "method" => "POST",
                        "content" => http_build_query($data)
                    )
                );
                $context = stream_context_create($options);
                $result = file_get_contents("https://icls.int.vpn/uauth/uauthenticate/session",false,$context);
                header("location: /");
            }
        }
        die("request_rejected::login_token_too_old");
    }
    else {
        die("request_rejected::invalid_login_token");
    }
}

?>