#!/usr/bin/perl
#
# cdprs.cgi: Sample perl cgi to collect cdpr data to a file
#
# Copyright (c) 2003 MonkeyMental.com

#######################################################


# Subroutine: ReadGetData
#
# On a get request, this is the function that gets the
# information from the browser, and puts it into a 
# string that the cgi script can use.

sub ReadGetData
{
	local(*queryString) = @_ if @_;
	$queryString = $ENV{"QUERY_STRING"};
	return 1;
}

#######################################################


# Subroutine: ReadPostData
#
# On apost request, this is the function that gets the
# information from the browser, and puts in into a
# string that the cgi script can use

sub ReadPostData
{
	local(*queryString) = @_;
	local($contentLength);
	$contentLength = $ENV{"CONTENT_LENGTH"};

	if ($contentLength)
	{
		read(STDIN,$queryString,$contentLength);
	}

	return 1;
}

#######################################################


# Subroutine: DecodeData
#
# Since the information passed from the browser is
# encrypted, it must be decoded before use.  The method
# for encryption is as such:
#  Spaces are turned into plus signs (+)
#
#  Non-alphanumeric characters are turned into their
#  hex equivalent preceded by a percent sign (%)
#  (an apostrophe (') is %27)
#
# This function is called from ParseData

sub DecodeData
{
	local(*convert) = @_ if @_;

	# Replace all +'s with spaces
	$convert =~ s/\+/ /g;

	# Replace all hex values with the proper character
	$convert =~ s/%([0-9A-Fa-f]{2})/pack("c",hex($1))/ge;

	# Return success
	return 1;
}

#######################################################


# Subroutine: ParseData
#
# This function breaks the string recieved from 
# ReadGetData or ReadPostData into values that can
# be used later in the script.  It calls DecodeData
# to decode the encrypted strings.

sub ParseData
{
	local(*queryString) = @_ if @_;
	@Array = split(/&/,$queryString);

	foreach $curString(@Array)
	{
		($key, $value) = split(/=/, $curString);
		&DecodeData(*key);
		&DecodeData(*value);

		# To save off the values passed from the browser into known
		# variables, use the following format.
		#
		# if ($key eq "KeyName" && $value ne "")
		# {
		# 		$KeyName = $value;
		# }
		#
		if ($key eq "switch_ip" && $value ne "")
		{
			$switch_ip = $value;
		}
		if ($key eq "port" && $value ne "")
		{
			$port = $value;
		}
		if ($key eq "host" && $value ne "")
		{
			$host = $value;
		}
		if ($key eq "loc" && $value ne "")
		{
			$loc = $value;
		}

	}

	return 1;
}

#######################################################
# Defines

$logfile = ">>/tmp/cdprs.csv";

# Main()

# Let the browser know what type of information we are
# going to be sending back to it, common information 
# types are:
#	Content-type: text/html
#	Content-type: text/plain
#
# It is necessary to end the string with two CR/LF's 
# (\n\n)

print "Content-type: text/plain\n\n";


#######################################################

# Find out what type of request we are processing as 
# get and post requests use different methods to obtain
# the data. $requestType will either be "GET" or "POST"

$requestType = $ENV{"REQUEST_METHOD"};

#######################################################

# This is a POST request, so use ReadPostData
# ParseData is a common routine to both GET and POST 
# requests

# Not using a post interface...
if ($requestType eq "POST")
{
	&ReadPostData(*data);
	&ParseData(*data);
}

if ($requestType eq "GET")
{
	&ReadGetData(*data);
	&ParseData(*data);

	open(LOGFILE, $logfile);
	print(LOGFILE "Switch: $switch_ip, Port: $port, Host: $host, Location: $loc\n");
	close(LOGFILE);

}
