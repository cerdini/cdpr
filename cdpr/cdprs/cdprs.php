<?
/*
** cdprs.php - Sample PHP script to collect cdpr data to a file
**
** Copyright (c) 2003 MonkeyMental.com
*/

	header("Content-type: plain/text");

	$switch = $_GET["switch_ip"];
	$port = $_GET["port"];
	$host = $_GET["host"];
	$loc = $_GET["loc"];

	if(!$fh = fopen("/tmp/cdprs.txt", "a+b"))
	{
		printf("Error opening file\n");
		exit();
	}

	$cdprs = sprintf("Switch: %s Port: $port Host: $host Location: $loc\n", 
					  $switch, $port, $host, $loc);

	if(!fwrite($fh, $cdprs))
	{
		printf("Error writing data to file\n");
		fclose($fh);
		exit();
	}
	else
	{
		print("Update Sucessful\n");
	}

?>
