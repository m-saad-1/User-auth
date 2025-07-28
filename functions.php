<?php
// Redirect to login page if not logged in
function check_login() {
    if(!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true){
        header("location: login.php");
        exit;
    }
}

// Display navigation based on login status
function display_nav() {
    if(isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true){
        echo '<a href="logout.php" class="btn">Logout</a>';
    } else {
        echo '<a href="login.php" class="btn">Login</a>';
        echo '<a href="signup.php" class="btn btn-primary">Sign Up</a>';
    }
}
?>