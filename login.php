<?php
session_start();
session_regenerate_id(true); 

$error=0;
if (isset($_SESSION['error']) && ($_SESSION['error'] == 1))
{
	$error=1;
}


if ($error==1) 
{
	$error_msg = $_SESSION['error_msg'];
}


?>
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <!-- Meta, title, CSS, favicons, etc. -->
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <title>WAF Dashboard </title>

    <!-- Bootstrap -->
    <link href="../vendors/bootstrap/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link href="../vendors/font-awesome/css/font-awesome.min.css" rel="stylesheet">
    <!-- NProgress -->
    <link href="../vendors/nprogress/nprogress.css" rel="stylesheet">
    <!-- Animate.css -->
    <link href="../vendors/animate.css/animate.min.css" rel="stylesheet">
	<link rel="stylesheet" type="text/css" href="additional.css" />	
    <!-- Custom Theme Style -->
    <link href="../build/css/custom.min.css" rel="stylesheet">
  </head>

  <body class="login">
    <div>
      <a class="hiddenanchor" id="signup"></a>
      <a class="hiddenanchor" id="signin"></a>

      <div class="login_wrapper">
        <div class="animate form login_form">
          <section class="login_content">
            <form action="auth.php" method="post">
              <h1>Login Form</h1>
 
              <div>
                <input type="text" class="form-control margin15px" name="username" placeholder="Username" required=""/>
              </div>
               <div>
                <input type="password" class="form-control margin5px" name="password" placeholder="Password" required=""/>
              </div>
              <div>
                <button class="btn btn-default submit" style="float:right">Log in</button>
              </div>

              <div class="clearfix"></div>

              <div class="separator">
				<?php  
					if ($error>0)
					{
						echo '<br>';
						echo '<strong style="float:left; color:red">'.$error_msg.'</strong>';
						echo '<br>';              
					}   
				?>
                <div class="clearfix"></div>
                <br />

                <div>
                  <h1><i class="fa fa-dashboard"></i>  ASM Policies Audit Tool </h1>
           		 by <br> <a href="https://www.linkedin.com/in/kostas-skenderidis">Kostas Skenderidis</a>

                </div>
              </div>
            </form>
          </section>
        </div>

        
      </div>
    </div>
  </body>
</html>