<?php
$env = parse_ini_file(__DIR__ . '/../.env.ini'); 

define('DB_SERVER', $env['DB_SERVER']);
define('DB_USER', $env['DB_USER']);
define('DB_PASS', $env['DB_PASS']);
define('DB_NAME', $env['DB_NAME']);

$con = mysqli_connect(DB_SERVER, DB_USER, DB_PASS, DB_NAME);

// Check connection
if (mysqli_connect_errno()) {
    echo "Failed to connect to MySQL: " . mysqli_connect_error();
    exit;
}
