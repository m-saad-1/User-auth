<?php
session_start();

// Database configuration
define('DB_SERVER', 'sql103.infinityfree.com');
define('DB_USERNAME', 'if0_39578880');
define('DB_PASSWORD', 'YdXEFWpYRRMjvC4');
define('DB_NAME', 'if0_39578880_user_auth');

// Attempt to connect to MySQL database
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}

// Set charset
mysqli_set_charset($link, 'utf8mb4');
?>