<?php

session_start();
session_regenerate_id(true); 

if (!(isset($_SESSION['loggedin']) && $_SESSION['loggedin'] == true))
{
	header("Location: login.php"); 
	exit();
}


$violations_basic = array("HTTP protocol compliance failed","Evasion technique detected");

	if(!empty($_POST['convert']))
	{
		$analyze_convert = "yes";
		$violations_basic[] ="Failed to convert character";
	}
	else
		$analyze_convert = "no";


	if(!empty($_POST['response_code']))
	{
		$analyze_response_code = "yes";
		$violations_basic[] ="Illegal HTTP status in response";
	}
	else
		$analyze_response_code = "no";

	if(!empty($_POST['file_length']))
	{
		$analyze_file_length = "yes";
		$violations_basic[] ="Illegal URL length";
		$violations_basic[] ="Illegal POST data length";
		$violations_basic[] ="Illegal query string length";
		$violations_basic[] ="Illegal request length";		
	}
	else
		$analyze_file_length = "no";

	if(!empty($_POST['redirection']))
	{
		$analyze_redirection = "yes";
		$violations_basic[] ="Illegal redirection attempt";
	}
	else
		$analyze_redirection = "no";

	if(!empty($_POST['cookie_compliance']))
	{
		$analyze_cookie_compliance = "yes";
		$violations_basic[] ="Cookie not RFC-compliant";
	}
	else
		$analyze_cookie_compliance = "no";


	if(!empty($_POST['file_type']))
	{
		$analyze_file_type = "yes";
		$violations_basic[] ="Illegal file type";
	}
	else
		$analyze_file_type = "no";

	if(!empty($_POST['blacklisted']))
	{
		$analyze_blacklisted = "yes";
		$violations_basic[] ="IP is blacklisted";
	}
	else
		$analyze_blacklisted = "no";

	if(!empty($_POST['asm_cookie']))
	{
		$analyze_asm_cookie = "yes";
		$violations_basic[] ="Modified ASM cookie";
	}
	else
		$analyze_asm_cookie = "no";

	if(!empty($_POST['domain_cookie']))
	{
		$analyze_domain_cookie = "yes";
		$violations_basic[] ="Modified domain cookie(s)";
	}
	else
		$analyze_domain_cookie = "no";

	if(!empty($_POST['method']))
	{
		$analyze_method = "yes";
		$violations_basic[] ="Illegal method";
	}
	else
		$analyze_method = "no";


	if(!empty($_POST['header_length']))
	{
		$analyze_header_length = "yes";
		$violations_basic[] ="Illegal header length";
	}
	else
		$analyze_header_length = "no";

	if(!empty($_POST['cookie_length']))
	{
		$analyze_cookie_length = "yes";
		$violations_basic[] ="Illegal cookie length";
	}
	else
		$analyze_cookie_length = "no";


	if(!empty($_POST['ipi']))
	{
		$analyze_ipi = "yes";
		$violations_basic[] ="Access from malicious IP address";
	}
	else
		$analyze_ipi = "no";


	if(empty($_POST['http_only']))
		$analyze_http_only = "no";
	else
		$analyze_http_only = "yes";

	
	if(empty($_POST['secure']))
		$analyze_secure = "no";
	else
		$analyze_secure = "yes";


	if(empty($_POST['same_side']))
		$analyze_same_side = "no";
	else
		$analyze_same_side = "yes";


	if(!empty($_FILES['filetoinspect']))
	{
		if(FALSE === ($asm_policy_xml = file_get_contents($_FILES['filetoinspect']['tmp_name'])))
		{
			header("Location: index.php"); 
			exit();
		}
	}
   else 
   {
		header("Location: index.php"); 
		exit();
	}


$disabled_violations = array();
$disabled_violation[] = "none";	
$error = 0;
$warning = 0;
$info =0;
$score = 0;
$analysis = 'var data_analysis = [';
$msg="";

//$asm_policy_xml = file_get_contents('test.xml');
$asm_policy_xml = str_replace ('disabled</evasion_setting>', '<enabled>no</enabled></evasion_setting>',$asm_policy_xml);
$asm_policy_xml = str_replace ('enabled</evasion_setting>', '<enabled>yes</enabled></evasion_setting>',$asm_policy_xml);
$asm_policy_xml = str_replace ('disabled</http_protocol_compliance_setting>', '<enabled>no</enabled></http_protocol_compliance_setting>',$asm_policy_xml);
$asm_policy_xml = str_replace ('enabled</http_protocol_compliance_setting>', '<enabled>yes</enabled></http_protocol_compliance_setting>',$asm_policy_xml);
$arr = simplexml_load_string($asm_policy_xml);

//print_r($arr);
//exit();
/*******	Basic information on the policy - START	 *****/

$asm_device = (string)$arr->policy_version->device_name;
$asm_policy = (string)$arr->policy_version->policy_name;
$bigip_version = (string)$arr->attributes()->bigip_version;

if (substr( $bigip_version, 0, 4 ) !== "13.1")
{
	$analysis .='{"category":"Configuration", "name":"0", "msg": "ASM is on version ('.$bigip_version.'). It is recommended review if this pplatform can be upgraded to 13.1.", "severity":"info"},';
	$info++;
}
/*******	Basic information on the policy - END 	*****/

/*******	Enforcement mode - START	 *****/

$enforcement = (string)$arr->blocking->enforcement_mode;
if ($enforcement=="blocking")
{
	$score = 100;
	$analysis .='{"category":"Configuration", "name":"100", "msg": "The policy ('.$asm_policy.') is in Staging mode. Therefore ASM protection is off. Please review the policy", "severity":"error"},';
	$error++;
}
/*******	Enforcement mode - END 	*****/


/***** 		Analyze the Blocking Settings	- Start			******/

$count = 0;
$ids = $arr->blocking->violation ;
$data_blocking =  'var data_blocking = [';

foreach($ids as $var) {
	$name = (string)$var->attributes()->name;
	if (in_array($name, $violations_basic))
	{
		if ($count>0)
			$data_blocking .= ",";
		$data_blocking .='{"name":"'.$name.'","block":"'.$var->block.'", "alarm":"'.$var->alarm.'", "learn":"'.$var->learn.'"}';

		if ($var->block == "false" && $var->alarm == "false" && $var->learn == "false" )
		{
			$analysis .='{"category":"Configuration", "name":"2", "msg": "The violation ('. $name .') is disabled. It is recommended to enable this violation", "severity":"error"},';
			$error++;	
			$disabled_violation[] = $name;	
			$score +=2;
		}
		else
		{
			if ($var->block == "false")
			{
				$analysis .='{"category":"Configuration", "name":"2", "msg": "The violation ('. $name .') has blocking disabled .  It is recommended to enable blocking to provide the required protection", "severity":"error"},';
				$score +=2;
				$error++;
			}
			if ($var->alarm == "false")
			{
				$analysis .='{"category":"Configuration", "name":"0", "msg": "The violation ('. $name .') is recommended to have the logging enabled", "severity":"warning"},';
				$warning++;
			}
			if ($var->learn == "false")
			{
				$analysis .='{"category":"Configuration", "name":"0", "msg": "The violation ('. $name .') is recommended to have the learning enabled", "severity":"warning"},';
				$warning++;		
			}
		}
		$count++;
	}
}
$data_blocking .= ' ];';
$count_blocking = $count;
$count_blocking_disabled = count($disabled_violation)-1;


/***** 		Analyze the Blocking Settings	- End			******/


/***** 			Analyze Evasion Settings  - Start				******/
	
if (in_array("Evasion technique detected", $disabled_violation))
	$evasion_enabled = false;
else
	$evasion_enabled = true;

$count = 0;
$count_disabled = 0;

$data_evasion =  'var data_evasion = [';
$ids = $arr->blocking->evasion_setting ;

foreach($ids as $var) {

	$name = (string)$var->attributes()->name;

	if ($count>0)
		$data_evasion .= ",";

	if ($evasion_enabled)
		$data_evasion .='{"name":"'.$name.'","enabled":"'.$var->enabled.'"}';
	else
		$data_evasion .='{"name":"'.$name.'","enabled":"disabled"}';
		
	if ((string)$var->enabled=="no" && $evasion_enabled)
	{
	 	$count_disabled++;
	}
	$count++;
}
$data_evasion .='];';
$count_evasion = $count;
if ($evasion_enabled)
	$count_evasion_disabled = $count_disabled;
else
	$count_evasion_disabled = $count;


if ($count_disabled>=3 && $count_disabled<$count)
{
	$analysis .='{"category":"Configuration", "name":"2", "msg": "Most of the Evasion violations ('.$count_disabled.' out of '.$count.') are disabled. You might need to review the configuration.", "severity":"warning"},';
	$score +=2;
	$warning++;
}
if ($count_disabled>=1 && $count_disabled<4)
{
	$analysis .='{"category":"Configuration", "name":"0", "msg": "Only few of the Evasion violations ('.$count_disabled.' out of '.$count.') are disabled.", "severity":"info"},';
	$info++;
}
if ($count_disabled==$count && $evasion_enabled)
{
	$analysis .='{"category":"Configuration", "name":"5", "msg": "All Evasion violations ('.$count_disabled.' out of '.$count.') are disabled. You need to review the configuration.", "severity":"error"},';
	$score +=5;
	$error++;
}

/***** 			Analyze Evasion Settings	- End				******/



/***** 			Analyze HTTP Compliance Settings	- Start				******/

if (in_array("HTTP protocol compliance failed", $disabled_violation))
	$compliance_enabled = false;
else
	$compliance_enabled = true;		

$count = 0;
$count_disabled = 0;

$data_compliance = 'var data_compliance = [';
$ids = $arr->blocking->http_protocol_compliance_setting ;

foreach($ids as $var) {
	$name = (string)$var->attributes()->name;

	if ($count>0)
		$data_compliance .= ",";

	if ($compliance_enabled)	
		$data_compliance .='{"name":"'.$name.'","enabled":"'.$var->enabled.'"}';
	else
		$data_compliance .='{"name":"'.$name.'","enabled":"disabled"}';
	
	if ((string)$var->enabled=="no" && $compliance_enabled)
	{
	 	$count_disabled++;
	}
	$count++;
}
$data_compliance .='];';
$count_compliance = $count;

if ($compliance_enabled)
	$count_compliance_disabled = $count_disabled;
else
	$count_compliance_disabled = $count;


if ($count_disabled>=6 && $count_disabled<$count)
{
	$analysis .='{"category":"Configuration", "name":"1", "msg": "Most of the HTTP Compliance violations ('.$count_disabled.' out of '.$count.') are disabled. You might need to review the configuration.", "severity":"warning"},';
	$score +=1;
	$warning++;
}
if ($count_disabled>=1 && $count_disabled<6)
{
	$analysis .='{"category":"Configuration", "name":"0", "msg": "Only few of the HTTP Compliance violations ('.$count_disabled.' out of '.$count.') are disabled.", "severity":"info"},';
	 $info++;
}
if ($count_disabled==$count && $compliance_enabled)
{
	$analysis .='{"category":"Configuration", "name":"2", "msg": "All HTTP Compliance violations ('.$count_disabled.' out of '.$count.') are disabled. You need to review the configuration.", "severity":"warning"},';
	$score +=2;
	$warning++;
}
/***** 			Analyze HTTP Compliance Settings	- End				******/



/***** 			Analyze Methods	- Start				******/

if (in_array("Illegal method", $disabled_violation) || $analyze_method=="no")
	$method_enabled = false;
else
	$method_enabled = true;
	

$count = 0;
$ids = $arr->methods->method;
$data_methods =  'var data_methods = [';

foreach($ids as $var) {
	$name = (string)$var->attributes()->name;

	if ($count>0)
		$data_methods .= ",";
	$data_methods .= '{ "name" : "' . $name . '", "act_as" : "' . $var->act_as . '"}';

	if ($name == "DELETE" && $method_enabled )
	{
		$analysis .='{"category":"Methods", "name":"1", "msg": "The Method ('. $name .') is usually blocked. Please refer with your appliance team if this method is required.", "severity":"warning"},';
		$score +=1;
		$warning++;
	}
	$count++;	
}
$data_methods .= ' ];';

	if ($count >6 && $method_enabled)
	{
		$analysis .='{"category":"Methods", "name":"0", "msg": "Too many allowed HTTP methods are configured. Please refer with your application team to verify if all of the configured HTTP methods are required.", "severity":"info"},';
		$info++;
	}
/***** 			Analyze Methods  - End				******/


/***** 			Analyze the Response Codes	- Start				******/
if (in_array("Illegal HTTP status in response", $disabled_violation) || $analyze_response_code =="no")
	$response_enabled = false;
else
	$response_enabled = true;
	

$data_response =  'var data_response = [';
$count = 0;

$ids = $arr->allowed_response_code;
foreach($ids as $var) {
	if ($count>0)
		$data_response .= ",";
	$data_response .='{"name":"'.(string)$var.'"}';
	$count++;		

}
$data_response .= ' ];';

if ($count> 15 && $response_enabled)	
{
	$analysis .='{"category":"Response Codes", "name":"0", "msg": "You might want to review the number of (HTTP status codes) that are configured on this policy. Currently it is ('. $count .'), that is considered above average.", "severity":"info"},';
	$info ++;
}
/***** 			Analyze the Response Codes	- End				******/




/***** 			Analyze the Cookie Length Settings	- Start				******/
if (in_array("Illegal cookie length", $disabled_violation) || $analyze_cookie_length =="no")
	$cookie_length_enabled = false;
else
	$cookie_length_enabled = true;
	
	
$cookie_length_value = (int)$arr->cookie_settings->maximum_cookie_length;
if ($cookie_length_value == '0' && $cookie_length_enabled)
{
	$analysis .='{"category":"Buffer Overflow", "name":"0.5", "msg": "Cookie Length has not been configured.", "severity":"warning"},';
	$score +=0.5;
	$warning++;
}
/***** 			Analyze the Cookie Length Settings	- End				******/


/***** 			Analyze the HTTP Header Length Settings	- Start				******/
if (in_array("Illegal header length", $disabled_violation) || $analyze_header_length =="no")
	$header_length_enabled = false;
else
	$header_length_enabled = true;
	
$header_length_value = (int)$arr->header_settings->maximum_header_length;
if ($header_length_value == '0' && $header_length_enabled )
{
	$analysis .='{"category":"Buffer Overflow", "name":"0.5", "msg": "HTTP Header Length has not been configured.", "severity":"warning"},';
	$score +=0.5;
	$warning++;
}
/***** 			Analyze the HTTP Header Length Settings	- End				******/



/*****			Analyze File Type Settings	- Start				******/
if (in_array("Illegal file type", $disabled_violation) || $analyze_file_type=="no")
	$file_type_enabled = false;
else
	$file_type_enabled = true;

if ($analyze_file_length == "no" || in_array("Illegal URL length", $disabled_violation) || in_array("Illegal request length", $disabled_violation) || in_array("Illegal POST data length", $disabled_violation) || in_array("Illegal query string length", $disabled_violation))
	$file_length_enabled = false;
else
	$file_length_enabled = true;

$counter_staging = 0;
$count = 0;
$data_file = 'var data_file = [';
$ids = $arr->file_types->file_type;

foreach($ids as $var) {
	$name = (string)$var->attributes()->name;
	
	if ($count>0)
		$data_file .= ",";
	$data_file .='{"name":"'.$name.'","staging":"'.$var->in_staging.'","last_updated":"'.substr($var->last_updated, 0, 10).'","url_length":"'.$var->url_length.'","request_length":"'.$var->request_length.'","query_string_length":"'.$var->query_string_length.'","post_data_length":"'.$var->post_data_length.'"}';
	$count++;
	
	if($name=="*" && $file_type_enabled)
	{
		$analysis .='{"category":"File Types", "name":"5", "msg": "The wildcard File Type (*) has not been removed. This will prevent the File Types extensions to be enforced", "severity":"error"},';
		$score +=5;
		$error++;
	}
	
	if ((string)$var->in_staging=="true" && $file_length_enabled)
	{
	 	$analysis .='{"category":"File Types", "name":"0.5", "msg": "The File Type ('.$name.') is still on staging. This will prevent the File Lengths to be enforced.", "severity":"error"},';
		$score +=0.5;
		$error++;
		$counter_staging++;
		
	}
}
$data_file .=' ];';

if ($file_length_enabled)
	$count_staging_file=$counter_staging;
else
	$count_staging_file=$count;

$count_file=$count;
$count_staging_file=$counter_staging;
/*****			Analyze File Type Settings	- End				******/



/*****			Analyze URL Settings	- Start				******/
	
$counter_staging = 0;
$count = 0;
$data_url = 'var data_url = [';

$ids = $arr->urls->url;

foreach($ids as $var) {
	$name = (string)$var->attributes()->name;
	$protocol = (string)$var->attributes()->protocol;
	$type = (string)$var->attributes()->type;

	if ($count>0)
		$data_url .= ",";
	$data_url .='{"name":"'.$name.'","staging":"'.$var->in_staging.'","last_updated":"'.substr($var->last_updated, 0, 10).'","check_metachars":"'.$var->check_metachars.'","check_methods":"'.$var->check_methods.'","check_attack_signatures":"'.$var->check_attack_signatures.'","protocol":"'.$protocol.'"}';
	$count++;

	if ((string)$var->in_staging=="true")
	{
	 	$counter_staging++;
	}
}
$data_url .=' ];';


if ($counter_staging>=1)
{
	$analysis .='{"category":"URLs", "name":"5", "msg": "There are URLs still on staging ('.$counter_staging.' out of '.$count.'). This will prevent certain functionality such as attack signatures and URL meta-charactes to be enforced.", "severity":"error"},';
	$score +=5;
	$error++;
	
}

$count_url=$count;
$count_staging_url=$counter_staging;
/*****			Analyze URL Settings	- End				******/



/*****			Analyze Parameters Settings	- Start				******/

$counter_staging = 0;
$count = 0;
$data_param = 'var data_param = [';
$ids = $arr->parameters->parameter;

foreach($ids as $var) {
	$name = (string)$var->attributes()->name;
	$type = (string)$var->attributes()->type;
	if ($count>0)
		$data_param .= ",";
	$count++;
	
	if ((string)$var->in_staging=="true")
	{
	 	$counter_staging++;
		if ($name=="*")
		{
			$analysis .='{"category":"Parameters", "name":"30", "msg": "The (*) Parameter is still on staging. This will prevent certain functionality such as attack signatures, meta-charactes and file-uploads to be enforced.", "severity":"error"},';
			$score +=30;
			$error++;
		}
	}

	if ($var->check_attack_signatures=="false")
	{
		$analysis .='{"category":"Parameters", "name":"2", "msg": "Parameter ('.$name.') has the Attack Signatures disabled. This will prevent protection against known attacks.", "severity":"error"},';
		$score +=2;
		$error++;
	}
	
	if (array_key_exists('attack_signature', $var))
		$data_param .='{"name":"'.$name.'","staging":"'.$var->in_staging.'","last_updated":"'.substr($var->last_updated, 0, 10).'","check_metachars":"'.$var->check_metachars.'","is_sensitive":"'.$var->is_sensitive.'","check_attack_signatures":"'.$var->check_attack_signatures.'","sig_disabled":'.count($var->attack_signature).',"url":"*","protocol":"HTTP/HTTPS","type":"'.$type.'"}';
	else
		$data_param .='{"name":"'.$name.'","staging":"'.$var->in_staging.'","last_updated":"'.substr($var->last_updated, 0, 10).'","check_metachars":"'.$var->check_metachars.'","is_sensitive":"'.$var->is_sensitive.'","check_attack_signatures":"'.$var->check_attack_signatures.'","sig_disabled":0,"url":"*","protocol":"HTTP/HTTPS","type":"'.$type.'"}';
}


/*  Analyze the parameters within URLs   -----    START   */
$ids = $arr->urls->url;

foreach($ids as $var) {
	$url_name = (string)$var->attributes()->name;
	$protocol = (string)$var->attributes()->protocol;

	if(array_key_exists('parameter', $var))
	{
		
		foreach($var->parameter as $var_param) {

			$name = (string)$var_param->attributes()->name;
			$type = (string)$var_param->attributes()->type;
			if ($count>0)
				$data_param .= ",";
			$count++;

			if ((string)$var_param->in_staging=="true")
			{
				$counter_staging++;
				if ($name=="*")
				{
					$analysis .='{"category":"Parameters", "name":"30", "msg": "The (*) Parameter is still on staging. This will prevent certain functionality such as attack signatures, meta-charactes and file-uploads to be enforced.", "severity":"error"},';
					$score +=30;
					$error++;
				}
			}

			if ($var_param->check_attack_signatures=="false")
			{
				$analysis .='{"category":"Parameters", "name":"2", "msg": "Parameter ('.$name.') has the Attack Signatures disabled. This will prevent protection against known attacks.", "severity":"error"},';
				$score +=2;
				$error++;
			}

			if (array_key_exists('attack_signature', $var_param))
				$data_param .='{"name":"'.$name.'","staging":"'.$var_param->in_staging.'","last_updated":"'.substr($var_param->last_updated, 0, 10).'","check_metachars":"'.$var_param->check_metachars.'","is_sensitive":"'.$var_param->is_sensitive.'","check_attack_signatures":"'.$var_param->check_attack_signatures.'","sig_disabled":'.count($var_param->attack_signature).',"url":"'.$url_name.'","protocol":"'.$protocol.'", "type":"'.$type.'"}';
			else
				$data_param .='{"name":"'.$name.'","staging":"'.$var_param->in_staging.'","last_updated":"'.substr($var_param->last_updated, 0, 10).'","check_metachars":"'.$var_param->check_metachars.'","is_sensitive":"'.$var_param->is_sensitive.'","check_attack_signatures":"'.$var_param->check_attack_signatures.'","sig_disabled":0,"url":"'.$url_name.'","protocol":"'.$protocol.'", "type":"'.$type.'"}';

		}
		
	}
}


/*  Analyze the parameters within URLs  -----    END    */


$data_param .=' ];';

if ($counter_staging>=1)
{
	$analysis .='{"category":"Parameters", "name":"2", "msg": "There are Parameters still on staging ('.$counter_staging.' out of '.$count.'). This will prevent certain functionality such as attack signatures, meta-charactes and file-uploads to be enforced.", "severity":"error"},';
	$score +=10;
	$error++;
}

$count_param=$count;
$count_staging_param=$counter_staging;
/*****			Analyze Parameters Settings	- End				******/




/*****			Analyze Signature Set Settings	- Start				******/

$count = 0;
$data_sig_set = 'var data_sig_set = [';

$ids = $arr->attack_signatures->signature_set;

foreach($ids as $var) {
	$name = (string)$var->set->attributes()->name;

	if ($count>0)
		$data_sig_set .= ",";
	$data_sig_set .='{"name":"'.$name.'","block":"'.$var->block.'", "alarm":"'.$var->alarm.'", "learn":"'.$var->learn.'"}';

	if ($var->block == "false" && $var->alarm == "false" && $var->learn == "false")
	{
			$analysis .='{"category":"Signatures", "name":"5", "msg": "The signature set ('. $name .') has been disabled. Please check your configuration", "severity":"error"},';
			$score +=5;
			$error++;	
	}
	else
	{
		if ($var->block == "false")
		{
			$analysis .='{"category":"Signatures", "name":"5", "msg": "The signature set ('. $name .') needs to be enabled to provide the required protection", "severity":"error"},';
			$score +=5;
			$error++;
		}
	
		if ($var->alarm == "false")
		{
			$analysis .='{"category":"Signatures", "name":"0", "msg": "The signature set ('. $name .') is recommended to have the logging enabled.", "severity":"warning"},';
			$warning++;
		}
	
		if ($var->learn == "false")
		{
			$analysis .='{"category":"Signatures", "name":"0", "msg": "The signature set ('. $name .') is recommended to have the learning enabled.", "severity":"warning"},';
			$warning++;
		}
	}
	$count++;
}
$data_sig_set .=' ];';

/*****			Analyze signature Set Settings	- End				******/



/*****			Analyze Signature Settings	- Start				******/
$counter_staging = 0;
$counter_enabled = 0;
$count = 0;
$ids = $arr->attack_signatures->signature;

foreach($ids as $var) {

	if ((string)$var->enabled=="true" && (string)$var->in_staging=="true")
	{
	 	$counter_staging++;
	}
	if ((string)$var->enabled=="false")
	{
	 	$counter_enabled++;
	}
	$count++;
}

$signatures = '{"data": [{"signatures_applied":"'.$count.'","signatures_staging":"'.$counter_staging.'", "signatures_enabled":"'.$counter_enabled.'"}]}';

if ($counter_staging>=1 && $counter_staging<$count)
{
//	$analysis .='{"category":"Signatures", "name":"0", "msg": "There are Attack Signatures still on staging ('.$counter_staging.' out of '.$count.'). This will prevent known attacks from being identified and blocked.", "severity":"warning"},';
//	$warning++;
}

if ($counter_staging==$count)
{
	$analysis .='{"category":"Signatures", "name":"15", "msg": "All Attack Signatures are on on staging. This will prevent known attacks from being identified and blocked.", "severity":"error"},';
	$score +=15;
	$error++;
}

if ($counter_enabled>=1 && $counter_staging<$count)
{
//	$analysis .='{"category":"Signatures", "name":"0", "msg": "There are Attack Signatures globally disabled ('.$counter_staging.' out of '.$count.'). This will prevent known attacks from being identified and blocked.", "severity":"warning"},';
//	$warning++;
}

if ($counter_staging==$count)
{
	$analysis .='{"category":"Signatures", "name":"15", "msg": "All Attack Signatures are disabled. This will prevent known attacks from being identified and blocked.", "severity":"error"},';
	$score +=15;
	$error++;
}

$count_sig_staging = $counter_staging ;
$count_sig_enabled = $counter_enabled ;
$count_sig = $count ;

/*****			Analyze Signature Settings	- End				******/



/***** 			Analyze Redirection Domains Settings  - Start				******/
if (in_array("Illegal redirection attempt", $disabled_violation) || $analyze_redirection=="no")
	$redirection_enabled = false;
else
	$redirection_enabled = true;


if ($arr->redirection_protection->enabled == "false" && $redirection_enabled)
{
	$analysis .='{"category":"Redirection Domains", "name":"2", "msg": "Redirection Protection has been Disabled. This will prevent the Redirection Domains to be enforced", "severity":"error"},';
	$score +=2;
	$error++;
}

$data_redirection = 'var data_redirection = [';
$count = 0;
$ids = $arr->redirection_domain;

foreach($ids as $var) {
	$name = (string)$var->attributes()->name;

	if ($count>0)
		$data_redirection .= ",";
	$data_redirection .='{"name":"'.$name.'","include_subdomains":"'.$var->include_subdomains.'"}';

	if($name=="*" && $redirection_enabled && $arr->redirection_protection->enabled == "true")
	{
		$analysis .='{"category":"Redirection Domains", "name":"2", "msg": "The wildcard Redirection Domain (*) has not been removed. This will prevent the Redirection Domains to be enforced", "severity":"error"},';
		$score +=2;
		$error++;
	}	
	$count++;
}
$data_redirection .=' ];';

/***** 			Analyze Redirection Domains Settings	- End				******/




/***** 			Analyze Cookies Settings  - Start				******/
if (in_array("Modified domain cookie(s)", $disabled_violation) || $analyze_domain_cookie=="no")
	$mod_cookies_enabled = false;
else
	$mod_cookies_enabled = true;
	
$data_cookies = 'var data_cookies = [';
$count = 0;
$count_cookies=0;
$count_staging_cookies=0;
$ids = $arr->headers->allowed_modified_cookie;
$count_enforced_cookies = 0;

foreach($ids as $var) {
	$name = (string)$var->attributes()->name;

	if ($count>0)
		$data_cookies .= ",";
	$data_cookies .='{"name":"'.$name.'","in_staging":"'.$var->in_staging.'","enforcement_mode":"'.$var->enforcement_mode.'","http_only":"'.$var->http_only.'","secure":"'.$var->secure.'","check_signatures":"'.$var->check_signatures.'","same_site_attribute":"'.$var->same_site_attribute.'"}';

	if($name=="*" && $mod_cookies_enabled)
	{
		$analysis .='{"category":"Cookies", "name":"2", "msg": "The wildcard Cookie (*) has not been removed. This will not enforce verification of (Allowed Cookies)", "severity":"warning"},';
		$score +=2;
		$warning++;
	}

	if ($var->in_staging == "true" && $var->enforcement_mode == "enforce" && $mod_cookies_enabled )
	{
		$analysis .='{"category":"Cookies", "name":"0", "msg": "The cookie ('. $name .') is still on staging. This will prevent protection on the cookie.", "severity":"error"},';
		$count_staging_cookies++;
		$error++;
	}
	if ($var->http_only == "false" && $analyze_http_only =="yes")
	{
		$analysis .='{"category":"Cookies", "name":"0", "msg": "The cookie ('. $name .') has the (http_only) flag disabled. Using the HttpOnly flag when generating a cookie helps mitigate the risk of client side script accessing the protected cookie.", "severity":"warning"},';
		$warning++;
	}
	if ($var->secure == "false" && $analyze_secure =="yes")
	{
		$analysis .='{"category":"Cookies", "name":"0", "msg": "The cookie ('. $name .') has the (secure) flag disabled. The purpose of the (secure) flag is to prevent cookies from being observed by unauthorized parties due to the transmission of a the cookie in clear text.", "severity":"warning"},';
		$warning++;
	}
	if ($var->same_site_attribute == "none" && $analyze_same_side =="yes")
	{
		$analysis .='{"category":"Cookies", "name":"0", "msg": "The cookie ('. $name .') has the (same_site) flag disabled. SameSite prevents the browser from sending this cookie along with cross-site requests. The main goal is mitigate the risk of cross-origin information leakage.", "severity":"warning"},';
		$warning++;
	}
	if ($var->check_signatures == "false")
	{
		$analysis .='{"category":"Cookies", "name":"0", "msg": "The cookie ('. $name .') has attack signatures disabled. Please make sure that signatures are not required for this cookie.", "severity":"warning"},';
		$warning++;
	}

	if ($var->enforcement_mode == "enforce" )
	{
		$count_enforced_cookies++;
	}
	$count++;
	
			
}
$data_cookies .=' ];';
$count_cookies = $count;

if ($count_enforced_cookies==0 && $mod_cookies_enabled)
{
	$analysis .='{"category":"Cookies", "name":"3", "msg": "There are 0 enforced cookies. This will prevent protection against cookie modification", "severity":"error"},';
	$score +=3;
	$count_staging_cookies++;
	$error++;
}

/***** 			Analyze Cookies Settings	- End				******/



/***** 			Analyze IPI	- Start				******/

if (in_array("Access from malicious IP address", $disabled_violation) || $analyze_ipi=="no")
	$ipi_enabled = false;
else
	$ipi_enabled = true;

$count_ipi=0;
$idi = $arr->ip_reputation->enabled;
$idi = true;

if($idi == "false" && $ipi_enabled == true)
{
	$analysis .='{"category":"IP Intelligence", "name":"5", "msg": "IP Intelligence is not enabled. Enabling IP reduces the risk of your application getting attacked by malicious users.", "severity":"error"},';
	$score +=5;
	$error++;

}


$count_ipi_disabled=0;
$data_ipi = 'var data_ipi = [';
$count = 0;
$ids = $arr->ip_reputation->category;

foreach($ids as $var) {
	$name = (string)$var->attributes()->name;

	if ($count>0)
		$data_ipi .= ",";
	

	if (($var->block == "false" && $var->alarm == "false") && !($idi == "false") && $ipi_enabled )
	{
		
		$data_ipi .='{"name":"'.$name.'","block":"disabled", "alarm":"disabled"}';
		$analysis .='{"category":"IP Intelligence", "name":"1", "msg": "The IP Intelligence category ('. $name .') has been disabled. You need to be enable this in order to provide the required protection", "severity":"error"},';
		$score +=1;
		$error++;
		$count_ipi_disabled++;	
	}
	else
	{

		$data_ipi .='{"name":"'.$name.'","block":"'.$var->block.'", "alarm":"'.$var->alarm.'"}';
		if ($var->block == "false" && !($idi == "false") && $ipi_enabled)
		{
			$analysis .='{"category":"IP Intelligence", "name":"1", "msg": "The IP Intelligence category ('. $name .') needs to be enabled to provide the required protection", "severity":"error"},';
			$score +=1;
			$error++;
			$count_ipi_disabled++;
		}
		if ($var->alarm == "false" && !($idi == "false") && $ipi_enabled)
		{
			$analysis .='{"category":"IP Intelligence", "name":"0", "msg": "The IP Intelligence category ('. $name .') is recommended to have the logging enabled.", "severity":"warning"},';
			$warning++;
		}
	}
	$count++;
//	echo $count . "<br>" . $name;		
}
$data_ipi .=' ];';
$count_ipi = $count;
if (!($idi == "false") && $ipi_enabled )
	$count_ipi_disabled= $count_ipi_disabled;
else
	$count_ipi_disabled= $count;

/***** 			Analyze IPI  - End				******/





/***** 			Analyze Config Parameters  - End				******/

$learning_mode = $arr->policy_builder->track_site_changes->learning_mode;
$unstrusted = $arr->policy_builder->track_site_changes->untrusted->enabled;
if($unstrusted == "true" && $learning_mode=="Automatic")
{
	$analysis .='{"category":"Configuration", "name":"0", "msg": "For Automatic Deployments we recommend that in Tighten Policy you disable the learning from untrusted sources or increase it to 200", "severity":"info"},';
	$info++;
}

$unstrusted = (int)$arr->policy_builder->loosen_rule->untrusted->distinct_sources;
if($unstrusted <100)
{
	$analysis .='{"category":"Configuration", "name":"0", "msg": "We recommend that in Loosen Policy you increase the untrusted sources to a minimum of 500.", "severity":"info"},';
	$info++;
}

$learn_file_types = $arr->policy_builder_filetype->learn_file_types;
if(!($learn_file_types == "Always"))
{
	$analysis .='{"category":"Configuration", "name":"0", "msg": "We recommend that you change the File Types Learning from (Learn New File Types) to (Always).", "severity":"info"},';
	$info++;
}

$learn_urls = $arr->policy_builder_url->learn_urls;
if(!($learn_urls == "Never"))
{
	$analysis .='{"category":"Configuration", "name":"0", "msg": "We recommend that you change the URL Learning (Learn New URLs) to (Never).", "severity":"info"},';
	$info++;
}

$learn_redirection_domains = $arr->policy_builder_redirection_protection->learn_redirection_domains;
if(!($learn_redirection_domains == "Always"))
{
	$analysis .='{"category":"Configuration", "name":"0", "msg": "We recommend that you change the Redirection Domain Learning from (Never) to (Always).", "severity":"info"},';
	$info++;
}

$learn_parameters = $arr->policy_builder_parameter->learn_parameters;
if(!($learn_parameters == "When Violation Detected"))
{
	$analysis .='{"category":"Configuration", "name":"0", "msg": "We recommend that you change the Parameters Learning from (Learn New Parameters) to (When Violation Detected).", "severity":"info"},';
	$info++;
}

/***** 			Analyze Config Parameters  - End				******/

$i= (int)strlen($analysis) - 1;
$data_analysis = substr ($analysis, 0, $i);
$data_analysis .='];';


$data_staging = 'var data_staging = [{"name":"File Types", "total":"'. $count_file . '", "staging":"'. $count_staging_file  . '", "disabled":"n/a"}, {"name":"URLS", "total":"'. $count_url . '", "staging":"'. $count_staging_url  . '", "disabled":"n/a"}, {"name":"Parameters", "total":"'. $count_param . '", "staging":"'. $count_staging_param  . '", "disabled":"n/a"}, {"name":"Cookies", "total":"'. $count_cookies . '", "staging":"'. $count_staging_cookies  . '", "disabled":"n/a"}, {"name":"Blocking Settings", "total":"16", "staging":"n/a", "disabled":"'. $count_blocking_disabled  . '"} ,{"name":"Evasion", "total":"8", "staging":"n/a", "disabled":"'. $count_evasion  . '"}, {"name":"HTTP Compliance", "total":"'. $count_compliance  .'", "staging":"n/a", "disabled":"'. $count_compliance_disabled . '"},{"name":"IP Intelligence", "total":"'. $count_ipi . '", "staging":"n/a", "disabled":"'. $count_ipi_disabled  . '"}];';


	$final_score=100-$score;
	

	if ($final_score <40)
	{
		$bar_class = '<span class="badge" style="font-size:128px; padding:20px 36px;; background-color:red">F</span>';
	}
	if ($final_score >=40 && $final_score <55)
	{
		$bar_class = '<span class="badge " style="font-size:128px; padding:20px 36px;; background-color:orange ">D</span>';
	}
	if ($final_score >=55 && $final_score <70)
	{
		$bar_class = '<span class="badge" style="font-size:128px; padding:20px 36px;; background-color:gray;">C</span>';
	}
	if ($final_score >=70 && $final_score <90)
	{
		$bar_class = '<span class="badge" style="font-size:128px; padding:20px 36px;; background-color:#1D9B1E">B</span>';
	}			
	if ($final_score >=90 )
	{
		$bar_class = '<span class="badge" style="font-size:128px; padding:20px 36px;; background-color:#30CE31">A</span>';
	}	

//print_r($arr);
//exit();
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

    <title>ASM Policy Review </title>

    <!-- Bootstrap -->
    <link href="../vendors/bootstrap/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link href="../vendors/font-awesome/css/font-awesome.min.css" rel="stylesheet">
    <!-- NProgress -->
    <link href="../vendors/nprogress/nprogress.css" rel="stylesheet">
    <!-- iCheck -->
    <link href="../vendors/iCheck/skins/flat/green.css" rel="stylesheet">
	
    <!-- bootstrap-progressbar -->
    <link href="../vendors/bootstrap-progressbar/css/bootstrap-progressbar-3.3.4.min.css" rel="stylesheet">
    <!-- JQVMap -->
    <link href="../vendors/jqvmap/dist/jqvmap.min.css" rel="stylesheet"/>
    <!-- bootstrap-daterangepicker -->
    <link href="../vendors/bootstrap-daterangepicker/daterangepicker.css" rel="stylesheet">

    <!-- Custom Theme Style -->
    <link href="build/css/custom.css" rel="stylesheet">

    <!-- Datatables -->
    <link href="../vendors/datatables.net-bs/css/dataTables.bootstrap.min.css" rel="stylesheet">
    <link href="../vendors/datatables.net-buttons-bs/css/buttons.bootstrap.min.css" rel="stylesheet">
    <link href="../vendors/datatables.net-fixedheader-bs/css/fixedHeader.bootstrap.min.css" rel="stylesheet">
    <link href="../vendors/datatables.net-responsive-bs/css/responsive.bootstrap.min.css" rel="stylesheet">
    <link href="../vendors/datatables.net-scroller-bs/css/scroller.bootstrap.min.css" rel="stylesheet">
	<link rel="stylesheet" type="text/css" href="build/css/flags16.css" />
	<link rel="stylesheet" type="text/css" href="build/css/flags32.css" />
	<link rel="stylesheet" type="text/css" href="additional.css" />	

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
				<h3> Device: <span style="font-weight:200" class="asm_device"> <?php echo $asm_device; ?> </span> / ASM Policy: <span style="font-weight:200" class="asm_policy"> <?php echo $asm_policy; ?> </span>  </h3>
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
						  <li style="font-size:13px"><a href="audit.php"><span>Upload New Policy</span></a></li>
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
            <div class="col-md-3 col-sm-3 col-xs-12">
              <div class="x_panel">
                <div class="x_title">
                  <h2>Overview</h2>
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


		
					<div class="row tile_count" style="margin-bottom: 20px; text-align:center" >
						<div class="col-md-4 col-sm-4 col-xs-4 tile_stats_count">
						  <span class="count_top red"><i class="fa fa-times-circle"></i> <b>Error </b></span>
						  <div id="var_error" class="count red"><?php echo $error; ?></div>
						</div>
						<div class="col-md-4 col-sm-4 col-xs-4 tile_stats_count">
						  <span class="count_top orange" ><i class="fa fa-warning"></i> <b>Warning </b></span>
						  <div id="var_warning" class="count orange"><?php echo $warning; ?></div>
						</div>
						
						<div class="col-md-4 col-sm-4 col-xs-4 tile_stats_count">
						  <span class="count_top text-info"><i class="fa fa-info"></i> <b>Info </b></span>
						  <div id="var_info" class="count text-info"><?php echo $info; ?></div>
						</div>
					</div>

					<div class="row tile_count" style="margin-bottom: 20px; text-align:center" >
						<div class="col-md-4 col-sm-4 col-xs-4" style="padding-top: 62px; font-size: 24px">
							<span class="current_score hidden"><?php echo $final_score; ?></span>Score: 
						</div>
						<div class="col-md-4 col-sm-4 col-xs-4 ">
							<span class="score"> <?php echo $bar_class; ?> </span>
						</div>
						
						<div class="col-md-4 col-sm-4 col-xs-4 ">

						</div>
					</div>
				  
                </div>
              </div>
            </div>
		

            <div class="col-md-9 col-sm-9 col-xs-12">
                <div class="x_panel">
                  <div class="x_title">
                    <h2>Alerts</h2>
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

					<table id="suggestions" class="table table-striped table-bordered" style="width:100%">
						<thead>
						  <tr>
							<th style="width: 10px; text-align: center;"></th>
							<th>Suggestions</th>
							<th style="width: 15%; text-align: center;">Severity</th>
							<th style="width: 15%; text-align: center;">Category</th>
							<th style="width: 15px; text-align: center;"></th>
						  </tr>
						</thead>
					 </table>
						<!-- end content  -->

                  </div>
                </div>
              </div>
   
          </div>

		 
	  <div class="row">
		<div class="col-md-5 col-sm-5 col-xs-12">
		  <div class="x_panel tile">
			<div class="x_title">
			  <h2>Configuration Review</h2>
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
				<div class="" role="tabpanel" data-example-id="togglable-tabs">
					<ul id="myTab" class="nav nav-tabs bar_tabs" role="tablist">
						<li role="presentation" class="active"><a href="#tab_config" role="tab" data-toggle="tab" aria-expanded="true">Config</a>
						</li>
						<li role="presentation" class=""><a href="#tab_blocking" role="tab" data-toggle="tab" aria-expanded="true">Settings</a>
						</li>
						<li role="presentation" class=""><a href="#tab_evasion" role="tab" data-toggle="tab" aria-expanded="false">Evasion</a>
						</li>
						<li role="presentation" class=""><a href="#tab_compliance" role="tab" data-toggle="tab" aria-expanded="false">Compliance</a>
						</li>
						<li role="presentation" class=""><a href="#tab_methods" role="tab" data-toggle="tab" aria-expanded="false">Methods</a>
						</li>
						<li role="presentation" class=""><a href="#tab_ipi" role="tab" data-toggle="tab" aria-expanded="false">IPI</a>
						</li>
				  </ul>
						<div id="myTabContent" class="tab-content">
						<div role="tabpanel" class="tab-pane fade active in" id="tab_config" aria-labelledby="home-tab">

							 <!-- start content -->
							 <table id="config" class="table table-striped table-bordered" style="width:100%">
								<thead>
								  <tr>
									<th> Entity Type <i class="fa fa-info-circle" data-toggle="tooltip" data-original-title="Click for more info on attack" ></i></th>
									<th style="width: 15%; text-align: center;">Total</th>
									<th style="width: 15%; text-align: center;">Staging</th>
									<th style="width: 15%; text-align: center;">Disabled</th>
							  </tr>
								</thead>
							 </table>
							<!-- end content -->

						  </div>
						<div role="tabpanel" class="tab-pane fade" id="tab_blocking" aria-labelledby="home-tab">

							 <!-- start content -->
							 <table id="blocking" class="table table-striped table-bordered" style="width:100%">
								<thead>
								  <tr>
									<th>Blocking Settings</th>
									<th style="width: 15%; text-align: center;">Learn</th>
									<th style="width: 15%; text-align: center;">Alarm</th>
									<th style="width: 15%; text-align: center;">Block</th>
								
								  </tr>
								</thead>
							 </table>
							<!-- end content -->

						  </div>
						<div role="tabpanel" class="tab-pane fade" id="tab_evasion" aria-labelledby="profile-tab">
						  <div class="row" class="col-md-12 col-sm-12 col-xs-12">
							<!-- start content -->
						  <table id="evasion" class="table table-striped table-bordered" style="width:100%">
							  <thead>
								<tr>
									<th>Evasion Technique Name</th>
									<th style="width: 15%; text-align: center;">Enabled</th>
								</tr>
							  </thead>
							</table>
										  <!-- end content -->
							</div>
						  </div>
						<div role="tabpanel" class="tab-pane fade" id="tab_compliance" aria-labelledby="profile-tab">
							<!-- start content -->
							 <table id="compliance" class="table table-striped table-bordered" style="width:100%">
							  <thead>
								<tr>
								  <th>HTTP Protocol Compliance</th>
								  <th style="width: 15%; text-align: center;">Enabled</th>

								</tr>
							  </thead>
							</table>
							<!-- end content -->
						  </div>
						<div role="tabpanel" class="tab-pane fade" id="tab_methods" aria-labelledby="profile-tab">
							<!-- start content -->
							 <table id="methods" class="table table-striped table-bordered" style="width:100%">
								<thead>
									<tr>
										<th>Allowed HTTP Methods</th>									
										<th style="width: 25%; text-align: center;">Act As</th>										
									</tr>
								</thead>
							</table>
							<!-- end content -->
						</div>

					<div role="tabpanel" class="tab-pane fade" id="tab_ipi" aria-labelledby="profile-tab">
						<!-- start content -->
						 <table id="ipi" class="table table-striped table-bordered" style="width:100%">
							<thead>
								<tr>
									<th>IP Intelligence Category</th>
									<th style="width: 15%; text-align: center;">Alarm</th>
									<th style="width: 15%; text-align: center;">Block</th>										
								</tr>
							</thead>
						</table>
						<!-- end content -->					
					</div>

					</div>
				  </div>
			</div>
		  </div>
		</div>      

		<div class="col-md-7 col-sm-7 col-xs-12">
		  <div class="x_panel tile">
			<div class="x_title">
			  <h2>Configuration Review</h2>
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
				<div class="" role="tabpanel" data-example-id="togglable-tabs">
					<ul id="myTab" class="nav nav-tabs bar_tabs" role="tablist">
						<li role="presentation" class="active"><a href="#tab_file_type" role="tab" data-toggle="tab" aria-expanded="false">File Types</a>
						</li>
						<li role="presentation" class=""><a href="#tab_urls" role="tab" data-toggle="tab" aria-expanded="false">URLs</a>
						</li>
						<li role="presentation" class=""><a href="#tab_parameters" role="tab" data-toggle="tab" aria-expanded="false">Parameters</a>
						</li>
						<li role="presentation" class=""><a href="#tab_signatures" role="tab" data-toggle="tab" aria-expanded="false">Signatures Sets</a>
						</li>
						<li role="presentation" class=""><a href="#tab_cookies" role="tab" data-toggle="tab" aria-expanded="false">Cookies</a>
						</li>
						<li role="presentation" class=""><a href="#tab_redirection" role="tab" data-toggle="tab" aria-expanded="false">Redirection</a>
						</li>
						<li role="presentation" class=""><a href="#tab_response" role="tab" data-toggle="tab" aria-expanded="false">Response Codes</a>
						</li>
				  </ul>
					<div id="myTabContent" class="tab-content">
					<div role="tabpanel" class="tab-pane fade active in" id="tab_file_type" aria-labelledby="profile-tab">
					   <div class="row" class="col-md-12 col-sm-12 col-xs-12">
						<!-- start content -->
						<table id="file_type" class="table table-striped table-bordered" style="width:100%">
							<thead>
								<tr>
									<th style="width:13px;"></th>
									<th>File Type</th>
									<th style="width:13%; text-align:center;">Staging</th>
									<th style="width:13%; text-align:center;">URI <i class="fa fa-info-circle" data-toggle="tooltip" data-original-title="What is the allowed URI Length for each File Type"></i></th>
									<th style="width:13%; text-align:center;">Query <i class="fa fa-info-circle" data-toggle="tooltip" data-original-title="What is the allowed Query String Length for each File Type"></i></th>
									<th style="width:13%; text-align:center;">Post <i class="fa fa-info-circle" data-toggle="tooltip" data-original-title="What is the allowed Post Data Length for each File Type"></i></th>
								</tr>
							</thead>
						</table>
						<!-- end content -->
					   </div>
					  </div>
					<div role="tabpanel" class="tab-pane fade" id="tab_urls" aria-labelledby="profile-tab">
						 <!-- start content -->
						 <table id="urls" class="table table-striped table-bordered" style="width:100%">
							<thead>
								<tr>
									<th style="width:10px;"></th>
									<th style="width:40px; text-align:center;"></th>
									<th>URL</th>
									<th style="width:15%; text-align:center;">Staging</th>
									<th style="width:15%; text-align:center;">Signatures <i class="fa fa-info-circle" data-toggle="tooltip" data-original-title="If Attack Signatures have been enabled"></i></th>
									<th style="width:15%; text-align:center;">Meta-Char <i class="fa fa-info-circle" data-toggle="tooltip" data-original-title="If checking on Meta-characters has been enabled"></i></th>
								</tr>
							</thead>
						</table>
						<!-- end content -->
					</div>
					<div role="tabpanel" class="tab-pane fade" id="tab_parameters" aria-labelledby="profile-tab">
						<!-- start content -->
						 <table id="parameters" class="table table-striped table-bordered" style="width:100%">
							<thead>
							  <tr>
								<th style="width:10px;"></th>
								<th>Parameters</th>
								<th style="width:15%; text-align:center;">Staging</th>
								<th style="width:15%; text-align:center;">Signatures <i class="fa fa-info-circle" data-toggle="tooltip" data-original-title="If Attack Signatures have been enabled"></i></th>
								<th style="width:15%; text-align:center;">Meta-Char <i class="fa fa-info-circle" data-toggle="tooltip" data-original-title="If checking on Meta-characters has been enabled"></i></th>
								<th style="width:15%; text-align:center;">Disabled <i class="fa fa-info-circle" data-toggle="tooltip" data-original-title="How many Attack Signatures have been disabled for this parameter"></i></th>
							  </tr>
							</thead>
						  </table>
						<!-- end content -->
					</div>
					<div role="tabpanel" class="tab-pane fade" id="tab_signatures" aria-labelledby="profile-tab">
						<!-- start content -->
						 <table id="signatures" class="table table-striped table-bordered" style="width:100%">
								<thead>
								<tr>
									<th>Signature Sets</th>
									<th style="width: 10%; text-align: center;">Learn</th>
									<th style="width: 10%; text-align: center;">Alarm</th>
									<th style="width: 10%; text-align: center;">Block</th>								
								</tr>
							</thead>
						</table>
						<!-- end content -->
					</div>
					<div role="tabpanel" class="tab-pane fade" id="tab_cookies" aria-labelledby="profile-tab">
						<!-- start content -->
						 <table id="cookies" class="table table-striped table-bordered" style="width:100%">
							<thead>
								<tr>
									<th style="width: 15px; text-align: center;"></th>
									<th>Name</th>
									<th style="width: 15%; text-align: center;">Enforcement <i class="fa fa-info-circle" data-toggle="tooltip" data-original-title="Whether the cookie is on Enforced or Allowed mode"></i></th>
									<th style="width: 15%; text-align: center;">Staging</th>
									<th style="width: 15%; text-align: center;">Signatures <i class="fa fa-info-circle" data-toggle="tooltip" data-original-title="Whether or not attack signatures are enabled on the cookie"></i></th>									
								</tr>
							</thead>
						</table>
						<!-- end content -->
					</div>

					<div role="tabpanel" class="tab-pane fade" id="tab_redirection" aria-labelledby="profile-tab">
						<!-- start content -->
						 <table id="redirection" class="table table-striped table-bordered" style="width:100%">
							<thead>
								<tr>
									<th>Domain Name</th>
									<th style="width: 20%; text-align: center;">Include Subdomains</th>
								</tr>
							</thead>
						</table>
						<!-- end content -->					
					</div>
					<div role="tabpanel" class="tab-pane fade" id="tab_response" aria-labelledby="profile-tab">
					<!-- start content -->
					 <table id="response" class="table table-striped table-bordered" style="width:100%">
						<thead>
						  <tr>
							<th>Allowed HTTP Response Codes</th>
						  </tr>
						</thead>
					  </table>
					<!-- end content -->
					</div>					
					
					
				</div>
			</div>
		  </div>
		</div>   
	  </div>



        </div>
        <!-- /page content -->


        <!-- MODAL Start-->
   
		  <div class="modal fade bs-example-modal-lg" tabindex="-1" role="dialog" aria-hidden="true">
			<div class="modal-dialog modal-lg">
			  <div class="modal-content">

				<div class="modal-header">
				  <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">×</span>
				  </button>
				  <h4 class="modal-title" id="myModalLabel">Transaction Details</h4>
				</div>
				<div class="modal-body">
				  <h4>Please wait...</h4>
				  <img src="images/loading.gif" width="128" height="128">
				</div>
				<div class="modal-footer">
				  <button type="button" class="btn btn-primary" data-dismiss="modal">Close</button>
				</div>

			  </div>
			</div>
		  </div>
        <!-- MODAL End-->
		  
		  
		  
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
    <!-- FastClick -->

    <!-- NProgress -->
    <script src="../vendors/nprogress/nprogress.js"></script>
    <!-- Chart.js -->

    <!-- gauge.js -->
    <script src="../vendors/gauge.js/dist/gauge.min.js"></script>
    <!-- bootstrap-progressbar -->
    <script src="../vendors/bootstrap-progressbar/bootstrap-progressbar.min.js"></script>
    <!-- iCheck -->

    <!-- Skycons -->

    <!-- Flot -->

    <!-- Flot plugins -->

    <!-- DateJS -->
    <script src="../vendors/DateJS/build/date.js"></script>

    <!-- bootstrap-daterangepicker -->
    <script src="../vendors/moment/min/moment.min.js"></script>
    <script src="../vendors/bootstrap-daterangepicker/daterangepicker.js"></script>

    <!-- Custom Theme Scripts -->
    <script src="../build/js/custom.js"></script>

    <!-- Datatables -->
    <script src="../vendors/datatables.net/js/jquery.dataTables.min.js"></script>
    <script src="../vendors/datatables.net-bs/js/dataTables.bootstrap.min.js"></script>
    <script src="../vendors/datatables.net-buttons/js/dataTables.buttons.min.js"></script>
    <script src="../vendors/datatables.net-buttons-bs/js/buttons.bootstrap.min.js"></script>
    <script src="../vendors/datatables.net-buttons/js/buttons.flash.min.js"></script>
    <script src="../vendors/datatables.net-buttons/js/buttons.html5.min.js"></script>
    <script src="../vendors/datatables.net-buttons/js/buttons.print.min.js"></script>
    <script src="../vendors/datatables.net-fixedheader/js/dataTables.fixedHeader.min.js"></script>
    <script src="../vendors/datatables.net-keytable/js/dataTables.keyTable.min.js"></script>
    <script src="../vendors/datatables.net-responsive/js/dataTables.responsive.min.js"></script>
    <script src="../vendors/datatables.net-responsive-bs/js/responsive.bootstrap.js"></script>
    <script src="../vendors/datatables.net-scroller/js/dataTables.scroller.min.js"></script>
    <script src="../vendors/jszip/dist/jszip.min.js"></script>
    <script src="../vendors/pdfmake/build/pdfmake.min.js"></script>
    <script src="../vendors/pdfmake/build/vfs_fonts.js"></script> 


<script type="text/javascript">
function tooltip_init () {
  $(document).ready(function(){
  $('[data-toggle="tooltip"]').tooltip({
    placement : 'top'
  });
});
}
</script>


<script type="text/javascript">
function modal_init () {
  $(document).ready(function(){
  	 $('.modal_open').on( 'click', function (e) {
		$(".modal-body").html('<h4>Please wait...</h4> <img src="images/loading.gif" width="128" height="128">');
		$(".modal-body").load("log.php?term_name=support_id&term_value="+$(this).attr("id"));
		
  });
});
}
</script>




<!-- Fetch the details for the Statistics Panel -->			


<!-- Load Tables with data -->			

<script>

<?php	echo $data_evasion; ?>

	$(document).ready(function() {
		var table = $('#evasion').DataTable( {
			"data": data_evasion,
			"createdRow": function( row, data, dataIndex ) {
				if ( data['enabled'] == "yes" )
				  $('td', row).eq(1).html("<i class='fa fa-check-square-o fa-2x green'></i>");
				else 
				  $('td', row).eq(1).html("<i class='fa fa-minus-square-o fa-2x red' ></i>");
				if ( data['enabled'] == "disabled" )
				  $('td', row).eq(1).html("<i class='fa fa-circle fa-2x black'></i>");
			},
			  "columns": [
				{ "className": 'bold',"data": "name" },
				{ "className": 'attacks', "data": "enabled"}
				],
				"autoWidth": false,
				"processing": true,
				"language": {"processing": "Waiting.... " },
				"order": [[1, 'desc']]
		} );	

	} );
</script>

<script>
	<?php	echo $data_compliance; ?>

	$(document).ready(function() {
		var table = $('#compliance').DataTable( {
			"data": data_compliance,
			"createdRow": function( row, data, dataIndex ) {
				if ( data['enabled'] == "yes" )
				  $('td', row).eq(1).html("<i class='fa fa-check-square-o fa-2x green'></i>");
				else 
				  $('td', row).eq(1).html("<i class='fa fa-minus-square-o fa-2x red' ></i>");
				if ( data['enabled'] == "disabled" )
				  $('td', row).eq(1).html("<i class='fa fa-circle fa-2x black'></i>");
			  },
			  "columns": [
				{ "className": 'bold',"data": "name" },
				{ "className": 'attacks', "data": "enabled"}
				],
				"autoWidth": false,
				"processing": true,
				"language": {"processing": "Waiting.... " },
				"order": [[1, 'desc']]
		} );	

	} );
</script>	



<script>

	<?php echo $data_blocking; ?>

	$(document).ready(function() {
		var table = $('#blocking').DataTable( {
			"data": data_blocking,
			"createdRow": function( row, data, dataIndex ) {
				if ( data['learn'] == "true" )
				  $('td', row).eq(1).html("<i class='fa fa-check-square-o fa-2x green'></i>");
				else 
				  $('td', row).eq(1).html("<i class='fa fa-minus-square-o fa-2x red' ></i>");
				if ( data['alarm'] == "true" )
				  $('td', row).eq(2).html("<i class='fa fa-check-square-o fa-2x green'></i>");
				else 
				  $('td', row).eq(2).html("<i class='fa fa-minus-square-o fa-2x red' ></i>");
				if ( data['block'] == "true" )
				  $('td', row).eq(3).html("<i class='fa fa-check-square-o fa-2x green'></i>");
				else 
				  $('td', row).eq(3).html("<i class='fa fa-minus-square-o fa-2x red' ></i>");
			  },
			  "columns": [
				{ "className": 'bold', "data":"name" },
				{  "className": 'attacks', "data":"alarm"},
				{  "className": 'attacks', "data":"learn"},
				{  "className": 'attacks', "data":"block"}
				],
				"autoWidth": false,
				"processing": true,
				"language": {"processing": "Waiting.... " },
				"order": [[1, 'desc']]
		} );	
	} );
</script>	

<script>
	<?php	echo $data_response;	?>

	$(document).ready(function() {
		var table = $('#response').DataTable( {
			"data": data_response,
			"columns": [
				{ "className": 'bold',"data": "name" }
				],
				"autoWidth": false,
				"processing": true,
				"language": {"processing": "Waiting.... " }
		} );
	} );
</script>	

<script>

function format_file ( d ) {
    // `d` is the original data object for the row

    return '<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;" class="results_table" width="100%">'+
        '<tr>'+
          '<td class="title"><b>Overall Request Length:</b></td>'+
          '<td class="results">'+d.request_length+'</td>'+
        '</tr>'+
        '<tr>'+
          '<td class="title"><b>Last Updated:</b></td>'+
          '<td class="results">'+d.last_updated+'</td>'+
        '</tr>'+
        '</table>';
}

	<?php	echo $data_file;	?>



	$(document).ready(function() {
		var table = $('#file_type').DataTable( {
			"data": data_file,
			"createdRow": function( row, data, dataIndex ) {
				if ( data['staging'] == "true" )
				  $('td', row).eq(2).html("<i class='fa fa-flag fa-2x red'></i>");
				else 
				  $('td', row).eq(2).html("<i class='fa fa-times fa-2x' ></i>");
			  },
			  "columns": [
				{
					"className":      'details-control',
					"orderable":      false,
					"data":           null,
					"defaultContent": ''
				},
				{ "className": 'bold',"data": "name" },
				{ "className": 'attacks', "data": "staging"},
				{  "className": 'attacks',"data": "url_length"},
				{  "className": 'attacks',"data": "query_string_length"},
				{  "className": 'attacks',"data": "post_data_length"}
				],
				"autoWidth": false,
				"processing": true,
				"order": [[1, 'asc']]
		} );	

		
    $('#file_type tbody').on('click', 'td.details-control', function () {
        var tr = $(this).closest('tr');
        var row = table.row( tr );
 
        if ( row.child.isShown() ) {
            // This row is already open - close it
            row.child.hide();
            tr.removeClass('shown');
        }
        else {
            // Open this row
            row.child( format_file(row.data()) ).show();
            tr.addClass('shown');
        }
    } );
    
	} );
</script>


<script>

function format_url ( d ) {
    // `d` is the original data object for the row

    return '<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;" class="results_table" width="100%">'+
        '<tr>'+
          '<td class="title"><b>Last Updated:</b></td>'+
          '<td class="results">'+d.last_updated+'</td>'+
        '</tr>'+
        '<tr>'+
          '<td class="title"><b>Type:</b></td>'+
          '<td class="results">'+d.type+'</td>'+
        '</tr>'+
        '</table>';
}

	<?php	echo $data_url;	?>

	$(document).ready(function() {
		var table = $('#urls').DataTable( {
			"data": data_url,
			"createdRow": function( row, data, dataIndex ) {
				if ( data['staging'] == "true" )
				  $('td', row).eq(3).html("<i class='fa fa-flag fa-2x red'></i>");
				else 
				  $('td', row).eq(3).html("<i class='fa fa-times fa-2x' ></i>");
				if ( data['check_attack_signatures'] == "true" )
				  $('td', row).eq(4).html("<i class='fa fa-check-circle fa-2x green'></i>");
				else 
				  $('td', row).eq(4).html("<i class='fa fa-minus-circle fa-2x red' ></i>");
				if ( data['check_metachars'] == "true" )
				  $('td', row).eq(5).html("<i class='fa fa-check-circle fa-2x green'></i>");
				else 
				  $('td', row).eq(5).html("<i class='fa fa-minus-circle fa-2x red' ></i>");
			  },
			"columns": [
				{
					"className":      'details-control',
					"orderable":      false,
					"data":           null,
					"defaultContent": ''
				},
				{ "data": "protocol", "orderable":false,},
				{ "className": 'bold',"data": "name" },
				{ "className": 'attacks',"data": "staging"},
				{ "className": 'attacks',"data": "check_attack_signatures"},
				{ "className": 'attacks',"data": "check_metachars"}
				],
				"autoWidth": false,
				"processing": true,
				"order": [[2, 'asc']]
		} );	
		
    $('#urls tbody').on('click', 'td.details-control', function () {
        var tr = $(this).closest('tr');
        var row = table.row( tr );
 
        if ( row.child.isShown() ) {
            // This row is already open - close it
            row.child.hide();
            tr.removeClass('shown');
        }
        else {
            // Open this row
            row.child( format_url(row.data()) ).show();
            tr.addClass('shown');
        }
    } );
	} );
</script>


<script>

function format_parameter ( d ) {
    // `d` is the original data object for the row
	if (d.is_sensitive == "true" )
	  var is_sensitive ="<i class='fa fa-check-circle fa-2x green'></i>";
	else 
	   var is_sensitive ="<i class='fa fa-minus-circle fa-2x red' ></i>";

    return '<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;" class="results_table" width="100%">'+
        '<tr>'+
          '<td class="title"><b>Is Parameter Sensitive:</b></td>'+
          '<td class="results">'+is_sensitive+'</td>'+
        '</tr>'+
        '<tr>'+
          '<td class="title"><b>Last Updated:</b></td>'+
          '<td class="results">'+d.last_updated+'</td>'+
        '</tr>'+
        '<tr>'+
          '<td class="title"><b>Type:</b></td>'+
          '<td class="results">'+d.type+'</td>'+
        '</tr>'+
        '<tr>'+
          '<td class="title"><b>Protocol:</b></td>'+
          '<td class="results">'+d.protocol+'</td>'+
        '</tr>'+
        '<tr>'+
          '<td class="title"><b>URL:</b></td>'+
          '<td class="results">'+d.url+'</td>'+
        '</tr>'+
        '</table>';
}

	<?php	echo $data_param;	?>

	$(document).ready(function() {
		var table = $('#parameters').DataTable( {
			"data": data_param,
			"createdRow": function( row, data, dataIndex ) {
				if ( data['staging'] == "true" )
				  $('td', row).eq(2).html("<i class='fa fa-flag fa-2x red'></i>");
				else 
				  $('td', row).eq(2).html("<i class='fa fa-times fa-2x' ></i>");
				if ( data['check_attack_signatures'] == "true" )
				  $('td', row).eq(3).html("<i class='fa fa-check-circle fa-2x green'></i>");
				else 
				  $('td', row).eq(3).html("<i class='fa fa-minus-circle fa-2x red' ></i>");
				if ( data['check_metachars'] == "true" )
				  $('td', row).eq(4).html("<i class='fa fa-check-circle fa-2x green'></i>");
				else 
				  $('td', row).eq(4).html("<i class='fa fa-minus-circle fa-2x red' ></i>");
			  },
			  "columns": [
				{
					"className":      'details-control',
					"orderable":      false,
					"data":           null,
					"defaultContent": ''
				},
				{ "className": 'bold',"data": "name" },
				{  "className": 'attacks',"data": "staging"},
				{  "className": 'attacks',"data": "check_attack_signatures"},
				{  "className": 'attacks',"data": "check_metachars"},
				{  "className": 'attacks',"data": "sig_disabled"}
				],
				"autoWidth": false,
				"processing": true,
				"language": {"processing": "Waiting.... " },
				"order": [[1, 'asc']]
		} );	

    $('#parameters tbody').on('click', 'td.details-control', function () {
        var tr = $(this).closest('tr');
        var row = table.row( tr );
 
        if ( row.child.isShown() ) {
            // This row is already open - close it
            row.child.hide();
            tr.removeClass('shown');
        }
        else {
            // Open this row
            row.child( format_parameter(row.data()) ).show();
            tr.addClass('shown');
        }
    } );


	} );
</script>

<script>

	<?php	echo $data_staging; ?>


	$(document).ready(function() {
		var table = $('#config').DataTable( {
			"data": data_staging,
			"columns": [
				{ "className": 'bold',"data": "name" },
				{  "className": 'attacks',"data": "total"},
				{  "className": 'attacks',"data": "staging"},
				{  "className": 'attacks',"data": "disabled"}
				],
				"autoWidth": false,
				"processing": true,
				"language": {"processing": "Waiting.... " }
		} );	

	} );
</script>



<script>

	<?php	echo $data_sig_set;	?>

	$(document).ready(function() {
		var table = $('#signatures').DataTable( {
			"data": data_sig_set,
			"createdRow": function( row, data, dataIndex ) {
				if ( data['learn'] == "true" )
				  $('td', row).eq(1).html("<i class='fa fa-check-circle fa-2x green'></i>");
				else 
				  $('td', row).eq(1).html("<i class='fa fa-minus-circle fa-2x red' ></i>");
				if ( data['alarm'] == "true" )
				  $('td', row).eq(2).html("<i class='fa fa-check-circle fa-2x green'></i>");
				else 
				  $('td', row).eq(2).html("<i class='fa fa-minus-circle fa-2x red' ></i>");
				if ( data['block'] == "true" )
				  $('td', row).eq(3).html("<i class='fa fa-check-circle fa-2x green'></i>");
				else 
				  $('td', row).eq(3).html("<i class='fa fa-minus-circle fa-2x red' ></i>");
			  },
			  "columns": [
				{ "className": 'bold',"data": "name" },
				{  "className": 'attacks',"data": "learn"},
				{  "className": 'attacks',"data": "alarm"},
				{  "className": 'attacks',"data": "block"}
				],
				"autoWidth": false,
				"processing": true,
				"language": {"processing": "Waiting.... " }
		} );	

	} );
</script>


<script>

function format_cookie ( d ) {
    // `d` is the original data object for the row
			if (d.http_only == "true" )
			  var http_only ="<i class='fa fa-check-circle fa-2x green'></i>";
			else 
			   var http_only ="<i class='fa fa-minus-circle fa-2x red' ></i>";
			if ( d.secure == "true" )
			  var secure ="<i class='fa fa-check-circle fa-2x green'></i>";
			else 
			   var secure ="<i class='fa fa-minus-circle fa-2x red' ></i>";

    return '<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;" class="results_table" width="100%">'+
        '<tr>'+
          '<td class="title"><b>Http_Only Cookie:</b></td>'+
          '<td class="results">'+http_only+'</td>'+
        '</tr>'+
        '<tr>'+
          '<td class="title"><b>Secure Cookie:</b></td>'+
          '<td class="results">'+secure+'</td>'+
        '</tr>'+
        '<tr>'+
          '<td class="title"><b>Same Side Cookie Attribute:</b></td>'+
          '<td class="results"><b>'+d.same_site_attribute+'</b></td>'+
        '</tr>'+
        '</table>';
}
 

	<?php 	echo $data_cookies;	?>
 

$(document).ready(function() {
	var table = $('#cookies').DataTable( {
		"data": data_cookies,
		"createdRow": function( row, data, dataIndex ) {
			if ( data['in_staging'] == "true" )
			  $('td', row).eq(3).html("<i class='fa fa-flag fa-2x red'></i>");
			else 
			  $('td', row).eq(3).html("<i class='fa fa-times fa-2x' ></i>");				  
			if ( data['check_signatures'] == "true" )
			  $('td', row).eq(4).html("<i class='fa fa-check-circle fa-2x green'></i>");
			else 
			  $('td', row).eq(4).html("<i class='fa fa-minus-circle fa-2x red' ></i>");

		  },
		  "columns": [
		    {
                "className":      'details-control',
                "orderable":      false,
                "data":           null,
                "defaultContent": ''
            },
			{ "className": 'bold',"data": "name" },
			{  "className": 'attacks',"data": "enforcement_mode"},
			{  "className": 'attacks',"data": "in_staging"},
			{  "className": 'attacks',"data": "check_signatures"}
			],
			"autoWidth": false,
			"processing": true,
			"language": {"processing": "Waiting.... " },
			"order": [[1, 'asc']]
		} );	

    $('#cookies tbody').on('click', 'td.details-control', function () {
        var tr = $(this).closest('tr');
        var row = table.row( tr );
 
        if ( row.child.isShown() ) {
            // This row is already open - close it
            row.child.hide();
            tr.removeClass('shown');
        }
        else {
            // Open this row
            row.child( format_cookie(row.data()) ).show();
            tr.addClass('shown');
        }
    } );


	} );
</script>

<script>

	<?php	echo $data_ipi;	?>
	
	$(document).ready(function() {
		var table = $('#ipi').DataTable( {
			"data": data_ipi,
			"createdRow": function( row, data, dataIndex ) {
				if ( data['alarm'] == "true" )
				  $('td', row).eq(1).html("<i class='fa fa-check-square-o fa-2x green'></i>");
				else 
				  $('td', row).eq(1).html("<i class='fa fa-minus-square-o fa-2x red' ></i>");
				if ( data['block'] == "true" )
				  $('td', row).eq(2).html("<i class='fa fa-check-square-o fa-2x green'></i>");
				else 
				  $('td', row).eq(2).html("<i class='fa fa-minus-square-o fa-2x red' ></i>");
				if ( data['alarm'] == "disabled" )
				  $('td', row).eq(1).html("<i class='fa fa-circle fa-2x black'></i>");
				if ( data['block'] == "disabled" )
				  $('td', row).eq(2).html("<i class='fa fa-circle fa-2x black'></i>");


			  },			
			"columns": [
				{ "className": 'bold',"data": "name" },
				{  "className": 'attacks',"data": "alarm"},
				{  "className": 'attacks',"data": "block"}
				],
				"autoWidth": false,
				"processing": true,
				"language": {"processing": "Waiting.... " }
		} );	

	} );
</script>

<script>

	<?php 	echo $data_redirection;	?>

	$(document).ready(function() {
		var table = $('#redirection').DataTable( {
			"data": data_redirection,
			"columns": [
				{ "className": 'bold',"data": "name" },
				{  "className": 'attacks',"data": "include_subdomains"}
				],
				"autoWidth": false,
				"processing": true,
				"language": {"processing": "Waiting.... " }
		} );	

	} );
</script>

<script>

	<?php echo $data_methods; ?>

	$(document).ready(function() {
		var table = $('#methods').DataTable( {
			"data": data_methods,
			"columns": [
				{ "className": 'bold',"data": "name" },
				{  "className": 'attacks',"data": "act_as"}
				],
				"autoWidth": false,
				"processing": true,
				"language": {"processing": "Waiting.... " }
		} );	

	} );
</script>

<script>

	<?php	echo $data_analysis;	?>
	
	$(document).ready(function() {
			var table = $('#suggestions').DataTable( {
			"data": data_analysis,
			"createdRow": function( row, data, dataIndex ) {
				if ( data['severity'] == "error" )
				  $('td', row).eq(0).html("<i class='fa fa-times-circle fa-2x red'></i>");
				if ( data['severity'] == "warning" )
				  $('td', row).eq(0).html("<i class='fa fa-warning fa-2x orange' ></i>");				  
				if ( data['severity'] == "info" )
				  $('td', row).eq(0).html("<i class='fa fa-info-circle fa-2x' ></i>");
				  $('td', row).eq(4).html("<i class='fa fa-trash fa-2x' ></i>");  
			  },

			"columns": [
				{"className":'attacks',"data":"severity"},
				{"data": "msg" },
				{ "className": 'attacks',"data": "severity"},
				{ "className": 'attacks',"data": "category"},
				{ "className": 'delete_button',"data": null},
				{ "data": "name"}
				],
				"columnDefs": [
				{
				  "targets": [5],
				  "visible": false
				}
				],				
				"autoWidth": false,
				"processing": true,
				"order": [[2, 'asc']]
		} );	

		$('#suggestions tbody').on( 'click', '.delete_button', function () {

    	   	var idx = table.row(this).index();
    	   	var data = table.cell( idx, 2).data();
    	   	var delta_score = parseInt(table.cell( idx, 5).data());
    	   	var error = $("#var_error").text();   	   
    	   	var warning = $("#var_warning").text();
    	   	var info = $("#var_info").text();
    	   	var current_score = parseInt($(".current_score").text());
    	   	var new_score = current_score + delta_score;
    	   	if(data=="error")
    	   	{
    	   		error = error - 1;
    	   		$("#var_error").html(error); 
    	   	}
    	   	   	   
    	   	if(data=="warning")
    	   	{
    	   		warning = warning - 1;
    	   		$("#var_warning").html(warning); 
    	   	}    	   	
    	   	if(data=="info")
    	   	{
    	   		info = info - 1;
    	   		$("#var_info").html(info); 
    	   	}   
    	   	$(".current_score").html(new_score);
    	   	
			if (new_score <40)
			{
				$(".score").html('<span class="badge" style="font-size:128px; padding:20px 36px;; background-color:red">F</span>');
			}
			if (new_score >=40 && new_score <55)
			{
				$(".score").html('<span class="badge" style="font-size:128px; padding:20px 36px;; background-color:orange ">D</span>');
			}
			if (new_score >=55 && new_score <70)
			{
				$(".score").html('<span class="badge" style="font-size:128px; padding:20px 36px;; background-color:gray;">C</span>');
			}
			if (new_score >=70 && new_score <85)
			{
				$(".score").html('<span class="badge" style="font-size:128px; padding:20px 36px;; background-color:#1D9B1E">B</span>');
			}			
			if (new_score >=85 )
			{
				$(".score").html('<span class="badge" style="font-size:128px; padding:20px 36px;; background-color:#30CE31">A</span>');
			}	

    	   	table.row(this).remove().draw( false );
    	   	
    } );

	} );
</script>



  </body>
</html>
