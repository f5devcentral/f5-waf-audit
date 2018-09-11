<?php
session_start();
session_regenerate_id(true); 

$error=0;
if (!(isset($_SESSION['loggedin']) && $_SESSION['loggedin'] == true))
{
	header("Location: login.php"); 
	exit();
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
	<link rel="icon" href="images/favicon.ico" type="image/ico" />

    <title>ASM Policies Review </title>


    <!-- Bootstrap -->
    <link href="../vendors/bootstrap/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link href="../vendors/font-awesome/css/font-awesome.min.css" rel="stylesheet">
    <!-- NProgress -->
    <link href="../vendors/nprogress/nprogress.css" rel="stylesheet">
    <!-- iCheck -->
    <link href="../vendors/iCheck/skins/flat/green.css" rel="stylesheet">
    <!-- bootstrap-wysiwyg -->
    <link href="../vendors/google-code-prettify/bin/prettify.min.css" rel="stylesheet">
    <!-- Select2 -->
    <link href="../vendors/select2/dist/css/select2.min.css" rel="stylesheet">
    <!-- Switchery -->
    <link href="../vendors/switchery/dist/switchery.min.css" rel="stylesheet">
    <!-- starrr -->
    <link href="../vendors/starrr/dist/starrr.css" rel="stylesheet">
    <!-- bootstrap-daterangepicker -->
    <link href="../vendors/bootstrap-daterangepicker/daterangepicker.css" rel="stylesheet">

    <!-- Custom Theme Style -->
    <link href="../build/css/custom.min.css" rel="stylesheet">


    <!-- Bootstrap -->
    <link href="../vendors/bootstrap/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link href="../vendors/font-awesome/css/font-awesome.min.css" rel="stylesheet">
  
	<link href="../vendors/switchery/dist/switchery.min.css" rel="stylesheet">
    <!-- Custom Theme Style -->
    <link href="build/css/custom.css" rel="stylesheet">


  </head>

  <body class="nav-md">
    <div class="container body">
      <div class="main_container">

        <!-- page content -->
        <div class="right_col" role="main" style="margin-left: 0px;">
          <!-- top tiles -->

		<div class="row" style="margin: -10px -20px;">
		  <div class="nav_menu">

			  <div class="col-md-8 col-sm-8 col-xs-8">
				<h3> Audit your ASM Policy  </h3>
	 		  </div>
			  <div class="col-md-4 col-sm-4 col-xs-4">
			  
			  	<ul class="nav navbar-nav navbar-right">
					 <li class="">
					  <a href="" class="user-profile dropdown-toggle" data-toggle="dropdown" aria-expanded="false">
						<img src="user2.png" alt="">Admin
						<span class=" fa fa-angle-down"></span>
					  </a>
					  <ul class="dropdown-menu dropdown-usermenu pull-right">
						  <br>
						  <li style="font-size:13px"><a href=""><span>Upload New Policy</span></a></li>
						  <br>
						  <li style="font-size:13px"><a href="logout.php"><i class="fa fa-sign-out pull-right"></i> Log Out</a></li>
						<br>
					  </ul>
					</li>
                  </ul>
            	</div>
			</div>	
		</div>
        
        <div id="error-placement" style="display:none"></div>

		<div class="row">
            <div class="col-md-6 col-sm-6 col-xs-12">
              <div class="x_panel">
                <div class="x_title">
                  <h2>ASM Policy</h2>
                  <ul class="nav navbar-right panel_toolbox">
                    <li><a class="hide filter_icon" id=""><i class="fa fa-filter filter_icon_i"></i></a>
                    </li>
                    <li><a class="collapse-link"><i class="fa fa-chevron-up"></i></a>
                    </li>
                    <li><a class="close-link"><i class="fa fa-close"></i></a>
                    </li>
                  </ul>
                  <div class="clearfix"></div>
                </div>
                <div class="x_content">


				<form class="form-horizontal form-label-left" novalidate="" action="audit.php" method="post" enctype="multipart/form-data">
                      
                      <div class="item form-group">
                        <label class="control-label col-md-5 col-sm-3 col-xs-12">Select ASM Policy (XML):  
                        </label>
                        <input type="file" class="file" name="filetoinspect" lang="es" style="margin-top:8px;">
                      </div>
                      <div class="ln_solid"></div>


                      <p> Please select all checks that that you want to be performed on your ASM Policy
                      </p>
                      <div class="item form-group">


                        <label class="control-label col-md-3 col-sm-3 col-xs-12">Attack Signatures                        </label>
                        <div class="col-md-1 col-sm-1 col-xs-6">
                            <label style="margin-top:5px">
                              <input type="checkbox" class="js-switch" checked disabled="disabled" name="signatures"/>
                            </label>
                        </div>


                         <label class="control-label col-md-3 col-sm-3 col-xs-12">Protocol compliance 
                        </label>
                        <div class="col-md-1 col-sm-1 col-xs-6">
                            <label style="margin-top:5px">
                              <input type="checkbox" class="js-switch" checked disabled="disabled" name="compliance"/>
                            </label>
                        </div>
 
                          <label class="control-label col-md-3 col-sm-3 col-xs-12">Evasion techniques 
                        </label>
                        <div class="col-md-1 col-sm-1 col-xs-6">
                            <label style="margin-top:5px">
                              <input type="checkbox" class="js-switch" checked disabled="disabled" name="evasion"/>
                            </label>
                        </div>  
                        
                      </div>
 
                       <div class="item form-group">

                         <label class="control-label col-md-3 col-sm-3 col-xs-12">Modified ASM cookie 
                        </label>
                        <div class="col-md-1 col-sm-1 col-xs-6">
                            <label style="margin-top:5px">
                              <input type="checkbox" class="js-switch" checked disabled="disabled" name="asm_cookie"/>
                            </label>
                        </div>
  
                        
                        <label class="control-label col-md-3 col-sm-3 col-xs-12">Cookie RFC-compliant 
                        </label>
                        <div class="col-md-1 col-sm-1 col-xs-6">
                            <label style="margin-top:5px">
                              <input type="checkbox" class="js-switch" checked disabled="disabled" name="cookie_compliance"/>
                            </label>
                        </div>
 
                          <label class="control-label col-md-3 col-sm-3 col-xs-12">File Types
                        </label>
                        <div class="col-md-1 col-sm-1 col-xs-6">
                            <label style="margin-top:5px">
                              <input type="checkbox" class="js-switch" checked name="file_type"/>
                            </label>
                        </div> 
  
           
                      </div>

                          <label class="control-label col-md-3 col-sm-3 col-xs-12">File Type Lengths
                        </label>
                        <div class="col-md-1 col-sm-1 col-xs-6">
                            <label style="margin-top:5px">
                              <input type="checkbox" class="js-switch" checked name="file_length"/>
                            </label>
                        </div>
                        
                       <div class="item form-group">
                        <label class="control-label col-md-3 col-sm-3 col-xs-12">IP Intelligence
                        </label>
                        <div class="col-md-1 col-sm-1 col-xs-6">
                            <label style="margin-top:5px">
                              <input type="checkbox" class="js-switch" checked name="ipi"/>
                            </label>
                        </div>
 
                          <label class="control-label col-md-3 col-sm-3 col-xs-12">Illegal methods 
                        </label>
                        <div class="col-md-1 col-sm-1 col-xs-6">
                            <label style="margin-top:5px">
                              <input type="checkbox" class="js-switch" checked name="method"/>
                            </label>
                        </div>
 
                               
                      </div>

                       <div class="item form-group">
                        <label class="control-label col-md-3 col-sm-3 col-xs-12">Http_only Cookie(s) 
                        </label>
                        <div class="col-md-1 col-sm-1 col-xs-6">
                            <label style="margin-top:5px">
                              <input type="checkbox" class="js-switch" checked name="http_only"/>
                            </label>
                        </div>

 
                         <label class="control-label col-md-3 col-sm-3 col-xs-12">HTTP Response Codes
                        </label>
                        <div class="col-md-1 col-sm-1 col-xs-6">
                            <label style="margin-top:5px">
                              <input type="checkbox" class="js-switch" checked name="response_code"/>
                            </label>
                        </div>
 
                          <label class="control-label col-md-3 col-sm-3 col-xs-12">Modified cookie(s) 
                        </label>
                        <div class="col-md-1 col-sm-1 col-xs-6">
                            <label style="margin-top:5px">
                              <input type="checkbox" class="js-switch" checked name="domain_cookie"/>
                            </label>
                        </div>   
                       </div>


                       <div class="item form-group">
                        <label class="control-label col-md-3 col-sm-3 col-xs-12">Secure Cookie(s) 
                        </label>
                        <div class="col-md-1 col-sm-1 col-xs-6">
                            <label style="margin-top:5px">
                              <input type="checkbox" class="js-switch" checked name="secure"/>
                            </label>
                        </div>

                        <label class="control-label col-md-3 col-sm-3 col-xs-12">Cookie length 
                        </label>
                        <div class="col-md-1 col-sm-1 col-xs-6">
                            <label style="margin-top:5px">
                              <input type="checkbox" class="js-switch" checked name="cookie_length"/>
                            </label>
                        </div>
 
                          <label class="control-label col-md-3 col-sm-3 col-xs-12">HTTP header length 
                        </label>
                        <div class="col-md-1 col-sm-1 col-xs-6">
                            <label style="margin-top:5px">
                              <input type="checkbox" class="js-switch" checked name="header_length"/>
                            </label>
                        </div>
                        
                      </div>

                       <div class="item form-group">
                        <label class="control-label col-md-3 col-sm-3 col-xs-12">Same Side Cookie(s) 
                        </label>
                        <div class="col-md-1 col-sm-1 col-xs-6">
                            <label style="margin-top:5px">
                              <input type="checkbox" class="js-switch" checked name="same_side"/>
                            </label>
                        </div>

 
 
                          <label class="control-label col-md-3 col-sm-3 col-xs-12">Redirection attempts
                        </label>
                        <div class="col-md-1 col-sm-1 col-xs-6">
                            <label style="margin-top:5px">
                              <input type="checkbox" class="js-switch" checked name="redirection"/>
                            </label>
                        </div> 
                        
 
                          <label class="control-label col-md-3 col-sm-3 col-xs-12">Failed to convert character
                        </label>
                        <div class="col-md-1 col-sm-1 col-xs-6">
                            <label style="margin-top:5px">
                              <input type="checkbox" class="js-switch" checked name="convert"/>
                            </label>
                        </div>

                      </div>

                       <div class="item form-group">

                         <label class="control-label col-md-3 col-sm-3 col-xs-12">IP is blacklisted 
                        </label>
                        <div class="col-md-1 col-sm-1 col-xs-6">
                            <label style="margin-top:5px">
                              <input type="checkbox" class="js-switch" checked name="blacklisted"/>
                            </label>
                        </div>
                                                                     
                      </div>


                      <div class="ln_solid"></div>
                      <div class="form-group">
                        <div class="col-md-12 col-md-offset-9">
                          <button type="submit" class="btn btn-primary">Cancel</button>
                          <button id="send" type="submit" class="btn btn-success">Analyze</button>
                        </div>
                      </div>
                    </form>
				  
                </div>
              </div>
            </div>


            <div class="col-md-6 col-sm-6 col-xs-12">
              <div class="x_panel">
                <div class="x_title">
                  <h2>Interesting Material</h2>
                  <ul class="nav navbar-right panel_toolbox">
                    <li><a class="hide filter_icon" id=""><i class="fa fa-filter filter_icon_i"></i></a>
                    </li>
                    <li><a class="collapse-link"><i class="fa fa-chevron-up"></i></a>
                    </li>
                    <li><a class="close-link"><i class="fa fa-close"></i></a>
                    </li>
                  </ul>
                  <div class="clearfix"></div>
                </div>
                <div class="x_content">


				<p> <b>BIG-IP ASM/WAF Demo Series</b>. <br>This is a series of videos created by F5 worldwide field enablement team on how to create and manage advanced F5 ASM Policies. <br>Click <a href="https://www.youtube.com/playlist?list=PLyqga7AXMtPN8vZoZtvo6FbF1JLSUu6zn"> <b><u>here</u></b></a> to access all 40 videos of the Series. 
				
				</p>

					<div id="myCarousel" class="carousel slide" data-ride="carousel" data-interval="false">

					  <!-- Wrapper for slides -->
					  <div class="carousel-inner">
						<div class="item active">
						  <iframe width="100%" height="315" src="https://www.youtube.com/embed/CStuessqUR8" frameborder="0" allow="autoplay; encrypted-media" allowfullscreen></iframe>
						</div>

						<div class="item">
						  <iframe width="100%" height="315" src="https://www.youtube.com/embed/Jcd5OW-yd04" frameborder="0" allow="autoplay; encrypted-media" allowfullscreen></iframe>
						</div>

						<div class="item">
						  <iframe width="100%" height="315" src="https://www.youtube.com/embed/Q88xcCxfm0A" frameborder="0" allow="autoplay; encrypted-media" allowfullscreen></iframe>
						</div>


						<div class="item">
							<iframe width="100%" height="315" src="https://www.youtube.com/embed/Y-ZnmEr5OG8" frameborder="0" allow="autoplay; encrypted-media" allowfullscreen></iframe>
						</div>

						<div class="item">
							<iframe width="100%" height="315" src="https://www.youtube.com/embed/TvGG9U6cM_E" frameborder="0" allow="autoplay; encrypted-media" allowfullscreen></iframe>
						</div>

						<div class="item">
							<iframe width="100%" height="315" src="https://www.youtube.com/embed/f-pVO4nuKpI" frameborder="0" allow="autoplay; encrypted-media" allowfullscreen></iframe>
						</div>


					  </div>

					  <!-- Left and right controls -->
					  <a class="left carousel-control" href="#myCarousel" data-slide="prev">
						<span class="glyphicon glyphicon-chevron-left"></span>
						<span class="sr-only">Previous</span>
					  </a>
					  <a class="right carousel-control" href="#myCarousel" data-slide="next">
						<span class="glyphicon glyphicon-chevron-right"></span>
						<span class="sr-only">Next</span>
					  </a>
					</div>

			
			
				<br>
				<br>
				
				<p> <b>BIG-IP ASM/WAF Deployment suggestions</b>. <br>To help you get started and progress with a WAF, this article provides a continuum of security features—from good protection that’s easiest to implement to maximum protection that requires the most WAF skill—so that you can start defending against attacks today and advance your web application security as you learn to operate your WAF.

. <br>Click <a href="https://support.f5.com/csp/article/K07359270"> <b><u>here</u></b></a> to access the acticle. 

				
				  
                </div>
              </div>
            </div>		
   
          </div>

		 



		  
		  
		  
        <!-- footer content -->
        
        
        
        <footer style="margin-left: 0px;">
          <div class="pull-right">
            WAF Audit Tool - by <a href="https://www.linkedin.com/in/kostas-skenderidis">Kostas Skenderidis</a>
          </div>
          <div class="clearfix"></div>
        </footer>
        <!-- /footer content -->
      </div>
    </div>

    <!-- jQuery -->
    <script src="../vendors/jquery/dist/jquery.min.js"></script>
    <!-- Bootstrap -->
    <script src="../vendors/bootstrap/dist/js/bootstrap.min.js"></script>


    <script src="../vendors/bootstrap-wysiwyg/js/bootstrap-wysiwyg.min.js"></script>
    <script src="../vendors/jquery.hotkeys/jquery.hotkeys.js"></script>
    <script src="../vendors/google-code-prettify/src/prettify.js"></script>
    <!-- jQuery Tags Input -->
    <script src="../vendors/jquery.tagsinput/src/jquery.tagsinput.js"></script>
    <!-- Switchery -->
    <script src="../vendors/switchery/dist/switchery.min.js"></script>
    <!-- Select2 -->
    <script src="../vendors/select2/dist/js/select2.full.min.js"></script>
    <!-- Parsley -->
    <script src="../vendors/parsleyjs/dist/parsley.min.js"></script>
    <!-- Autosize -->
    <script src="../vendors/autosize/dist/autosize.min.js"></script>
    <!-- starrr -->
    <script src="../vendors/starrr/dist/starrr.js"></script>
    
    
    
    <!-- Custom Theme Scripts -->
    <script src="../build/js/custom.js"></script>
	

   <!-- jQuery -->
    <script src="../vendors/jquery/dist/jquery.min.js"></script>
    <!-- Bootstrap -->
    <script src="../vendors/bootstrap/dist/js/bootstrap.min.js"></script>
    <!-- FastClick -->
	<script src="../vendors/switchery/dist/switchery.min.js"></script>



  </body>
</html>
