<?php
require_once "config.php";
require_once "functions.php";
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Professional Auth System</title>
  <link rel="stylesheet" href="style.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
  <header class="header">
    <div class="container header-content">
      <a href="index.php" class="logo">AuthSystem</a>
      <nav class="nav">
        <?php if(isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true): ?>
          <a href="logout.php" class="btn btn-outline">Logout</a>
        <?php else: ?>
          <a href="login.php" class="btn btn-outline">Login</a>
          <a href="signup.php" class="btn btn-primary">Sign Up</a>
        <?php endif; ?>
      </nav>
    </div>
  </header>

  <main>
    <section class="hero">
      <div class="container">
        <h1>Welcome to Our Professional Auth System</h1>
        <p>A secure and elegant solution for user authentication and management</p>
        <?php if(isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true): ?>
          <div class="welcome-message">
            <p>Welcome back, <strong><?php echo htmlspecialchars($_SESSION['username']); ?></strong>!</p>
            <a href="logout.php" class="btn btn-outline" style="margin-top: 1rem;">Logout</a>
          </div>
        <?php else: ?>
          <div class="cta-buttons" style="margin-top: 2rem;">
            <a href="signup.php" class="btn btn-primary" style="margin-right: 1rem;">
              <i class="fas fa-user-plus"></i> Get Started
            </a>
            <a href="login.php" class="btn btn-outline">
              <i class="fas fa-sign-in-alt"></i> Login
            </a>
          </div>
        <?php endif; ?>
      </div>
    </section>
  </main>

  <footer class="footer">
    <div class="container">
      <p>&copy; <?php echo date("Y"); ?> Professional Auth System. All rights reserved.</p>
    </div>
  </footer>
</body>
</html>