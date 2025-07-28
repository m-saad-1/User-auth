<?php
require_once "config.php";

$username = $password = "";
$username_err = $password_err = $login_err = "";

if($_SERVER["REQUEST_METHOD"] == "POST"){
    if(empty(trim($_POST["username"]))){
        $username_err = "Please enter username.";
    } else{
        $username = trim($_POST["username"]);
    }

    if(empty(trim($_POST["password"]))){
        $password_err = "Please enter your password.";
    } else{
        $password = trim($_POST["password"]);
    }

    if(empty($username_err) && empty($password_err)){
        $sql = "SELECT id, username, password FROM users WHERE username = ?";
        
        if($stmt = mysqli_prepare($link, $sql)){
            mysqli_stmt_bind_param($stmt, "s", $param_username);
            $param_username = $username;
            
            if(mysqli_stmt_execute($stmt)){
                mysqli_stmt_store_result($stmt);
                
                if(mysqli_stmt_num_rows($stmt) == 1){
                    mysqli_stmt_bind_result($stmt, $id, $username, $hashed_password);
                    if(mysqli_stmt_fetch($stmt)){
                        if(password_verify($password, $hashed_password)){
                            session_start();
                            
                            $_SESSION["loggedin"] = true;
                            $_SESSION["id"] = $id;
                            $_SESSION["username"] = $username;
                            
                            header("location: index.php");
                        } else{
                            $login_err = "Invalid username or password.";
                        }
                    }
                } else{
                    $login_err = "Invalid username or password.";
                }
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }
            mysqli_stmt_close($stmt);
        }
    }
    mysqli_close($link);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login | Professional Auth System</title>
  <link rel="stylesheet" href="style.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
  <header class="header">
    <div class="container header-content">
      <a href="index.php" class="logo">AuthSystem</a>
      <nav class="nav">
        <a href="signup.php" class="btn btn-primary">Sign Up</a>
      </nav>
    </div>
  </header>

  <div class="auth-container">
    <div class="auth-card">
      <h2><i class="fas fa-sign-in-alt"></i> Login</h2>
      <p>Enter your credentials to access your account</p>

      <?php if(!empty($login_err)): ?>
        <div class="alert alert-danger">
          <i class="fas fa-exclamation-circle"></i> <?php echo $login_err; ?>
        </div>
      <?php endif; ?>

      <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
        <div class="form-group">
          <label for="username"><i class="fas fa-user"></i> Username</label>
          <input type="text" name="username" id="username" class="form-control <?php echo (!empty($username_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $username; ?>">
          <?php if(!empty($username_err)): ?>
            <span class="invalid-feedback"><i class="fas fa-exclamation-circle"></i> <?php echo $username_err; ?></span>
          <?php endif; ?>
        </div>
        
        <div class="form-group">
          <label for="password"><i class="fas fa-lock"></i> Password</label>
          <input type="password" name="password" id="password" class="form-control <?php echo (!empty($password_err)) ? 'is-invalid' : ''; ?>">
          <?php if(!empty($password_err)): ?>
            <span class="invalid-feedback"><i class="fas fa-exclamation-circle"></i> <?php echo $password_err; ?></span>
          <?php endif; ?>
        </div>
        
        <div class="form-group">
          <button type="submit" class="btn btn-primary" style="width: 100%;">
            <i class="fas fa-sign-in-alt"></i> Login
          </button>
        </div>
        
        <div class="text-center" style="margin-top: 1rem;">
          <p>Don't have an account? <a href="signup.php">Sign up here</a></p>
        </div>
      </form>
    </div>
  </div>

  <footer class="footer">
    <div class="container">
      <p>&copy; <?php echo date("Y"); ?> Professional Auth System. All rights reserved.</p>
    </div>
  </footer>
</body>
</html>