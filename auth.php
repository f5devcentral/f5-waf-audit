<?php

	session_start();

	if(empty($_POST['username']) || empty($_POST['password']))
	{
		header("Location: login.php"); /* Redirect browser */
		exit();
	}

	$user=$_POST["username"];
	$pass=$_POST["password"];

	
	if ($user!="admin" || $pass!="checkmypolicy")
	{

		header("Location: index.php"); /* Redirect browser */
	}
	else
	{
		$_SESSION['loggedin'] = true;
		header("Location: index.php"); /* Redirect browser */
		exit();
	}
?>