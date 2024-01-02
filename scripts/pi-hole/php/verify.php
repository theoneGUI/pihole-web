<?php
ini_set('session.gc_maxlifetime', 604800);
session_set_cookie_params(604800);

session_start();
require "/var/www/html/ipi/config.php";
require '/var/www/html/ipi/js/phpFunc.php';

if (isset($_SESSION["loggedin"])) {
    echo "already logged in as "+$_SESSION["username"];
}

$pdo = pdo_connect_mysqli();

if (isset($_POST["loneLoginToken"]) && !isset($_POST["session"])) {
     // Prepare a select statement
     $sql = "INSERT INTO tokens (tokenGiven,collateral) VALUES (?,?);";

     if($stmt = mysqli_prepare($link, $sql)){
        $collateral = $_POST["collateral"];
         // Bind variables to the prepared statement as parameters
         mysqli_stmt_bind_param($stmt, "ss", $token, $collateral);

         // Set parameters
         $token = $_POST["loneLoginToken"];

         if(mysqli_stmt_execute($stmt)){
            echo "success";
        }
        else {
            echo "failed";
        }
     }
     die();
}

if ($sessVars = json_decode(urldecode($_POST["session"]),true)) {
    $sql = "SELECT tokenGiven,collateral FROM tokens WHERE tokenGiven = ?;";

    if($stmt = mysqli_prepare($link, $sql)){
        // Bind variables to the prepared statement as parameters
        mysqli_stmt_bind_param($stmt, "s", $searchToken);
        $searchToken = $sessVars["loginToken"];
        $sessionId = $sessVars["sessionName"];

        if(mysqli_stmt_execute($stmt)){
            mysqli_stmt_store_result($stmt);
            if(mysqli_stmt_num_rows($stmt) == 1){
                mysqli_stmt_bind_result($stmt, $fetchedToken, $fetchedCollateral);
                if(mysqli_stmt_fetch($stmt)){
                    echo mysqli_connect_error();
                    if ($fetchedToken == $searchToken) {
                        $valid_tokens = array();
                        for ($i = 0; $i < 10; $i++) {
                            array_push($valid_tokens, hash("SHA512",($sessVars["id"] . $sessVars["username"] . gmdate("d-m-Y h:i:s", strtotime("-{$i} seconds")))));
                        }
                        if (in_array($searchToken,$valid_tokens)) {
                            $_SESSION = $sessVars;
                            $delsql = "DELETE FROM tokens WHERE tokenGiven = ?;";
                            $delStmt = mysqli_prepare($link, $delsql);
                            mysqli_stmt_bind_param($delStmt, "s", $fetchedToken);
                            mysqli_stmt_execute($delStmt);
                            $addUser = $pdo->prepare("INSERT INTO users (username) VALUES (?)");
                            $addUser->execute([$_SESSION["username"]]);

                            $handshake = hash("SHA256", ($fetchedCollateral . $_SERVER["REMOTE_ADDR"]));
                            $options = array(
                                    'http' => array(
                                    "header" => "Content-type: application/x-www-form-urlencoded\r\nX-ICLS-Session: ".$sessionId."\r\nX-ICLS-Handshake: ".$handshake."\r\n",
                                    "method" => "POST",
                                    "content" => http_build_query($data)
                                )
                            );
                            $context = stream_context_create($options);
                            $result = file_get_contents("https://security.thatonetechcrew.net/uauth/uauthenticate/session",false,$context);

                            header("location: https://ipi.thatonetechcrew.net/ipi");
                        }
                        else {
                            echo "request_rejected::login_token_too_old";
                        }
                    }
                }
            }
        }
       else {
           echo "request_rejected::invalid_login_token";
       }
    }
}

?>