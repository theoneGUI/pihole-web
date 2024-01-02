<?php
/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license.
*/

require_once 'func.php';
require_once 'persistentlogin_token.php';
require_once 'icls.php';
// Start a new PHP session (or continue an existing one)
start_php_session();

// Read setupVars.conf file
$setupVars = parse_ini_file('/etc/pihole/setupVars.conf');
// Try to read password hash from setupVars.conf
if (isset($setupVars['WEBPASSWORD'])) {
    $pwhash = $setupVars['WEBPASSWORD'];
} else {
    $pwhash = '';
}

function verifyPassword($pwhash, $use_api = false)
{
    return confederated_session($_COOKIE["ICLS_Sess"]);
}

$wrongpassword = !verifyPassword($pwhash, isset($api));
$auth = $_SESSION['auth'];
