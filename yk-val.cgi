#!/usr/bin/perl

use strict;
use warnings;
use Data::Dumper;
use MIME::Base64;
use Data::Uniqid qw (uniqid);
use Digest::MD5 qw (md5_hex);
use Digest::HMAC_SHA1 qw(hmac_sha1);
use Mcrypt;
use DBI;
use HTML::Entities qw(decode_entities);
use Time::HiRes qw(time);
use POSIX qw(strftime);


my $logfile = "/tmp/yk-val.log";
my $otp = '';
my $timeout = '';
my $nonce = '';
my $sl = '';
my $client = '';
my $h = '';
my $LOG;
my %db_data;
my $api_key;
my %request;

open_log($logfile);


if($ENV{'QUERY_STRING'}){
	print "Content-type:text/plain\r\n\r\n";
	my @pairs = split(/&/, $ENV{'QUERY_STRING'});
	my %FORM;
	foreach my $pair (@pairs){
	my ($name, $value) = split(/=/, $pair, 2);
		$value =~ tr/+/ /;
		$value =~ s/%(..)/pack("C", hex($1))/eg;
		$FORM{$name} = $value;
	}

	$client = decode_entities($FORM{id}) if($FORM{id});
	$otp = decode_entities($FORM{otp}) if($FORM{otp});
	$timeout = decode_entities($FORM{timeout}) if($FORM{timeout});
	$nonce = decode_entities($FORM{nonce}) if($FORM{nonce});
	$sl = decode_entities($FORM{sl}) if($FORM{sl});
	$h = decode_entities($FORM{h}) if($FORM{h});

}else{
	print "Content-type:text/plain\r\n\r\n";
	print "Err";
}

write_log("Validating request for $otp");

$otp = translate_dvorak($otp);


# Manually create nonce if not present
if($nonce eq '') {
	$nonce = md5_hex(uniqid(rand()));
	write_log("nonce not present in request, using generated nonce=$nonce");
}

#put above status msg when completed or failed
my %response_header = (t => getUTCTimeStamp(), otp => $otp, nonce => "$nonce", sl => 0 );

# Connect to databases
my %db = connect_db();

$request{otp}     = $otp;
$request{timeout} = $timeout;
$request{nonce}   = $nonce;
$request{sl}      = $sl;
$request{id}      = $client;
$request{h}       = $h;

check_request(%request);

# verify clientID and get "secret"
get_api_key($request{id});

# verify signature of request
check_client_signature(%request);

# decrypt yubikey and populate %db_data
my $decrypted_yubikey = decrypt_yubikey(%request);

# verify CRC of request
if(!crc_is_good($decrypted_yubikey)){
	write_log("CRC Error");
	send_reposnse('CRC error');
}

# make sure internalname from DB(if set) matches UID from request
compare_uid_with_internalname($decrypted_yubikey, $db_data{internalname});

# Extract request parameters
my %request_parameters = extract_params($decrypted_yubikey);

# nonce is not part of the OTP and we need it later so we add it manually to the request_parameters
$request_parameters{nonce} = $request{nonce};

# this seems redundant
#if($db_data{nonce} eq $request_parameters{nonce}){
#    send_response("nonce repeated");
#}

# Check if server counters are higher than those from the OTP, this should not happen i a one server environment 
if(counters_higher(\%db_data, \%request_parameters)){
	send_response("Server counters are higher than OTP counters"); # this should never happen
}

# Check if we have already received this OTP/nonce combination
if(counters_equal(%request_parameters) && $db_data{nonce} eq $request{nonce}){
	send_response('REPLAYED_REQUEST');
}

# Check if this OTP has been used previously
if(counters_higher_or_equal(%request_parameters)){
	send_response('REPLAYED_OTP');
}

# if we came this long OTP should be valid, so lets update the database
update_db_counters($db_data{key_id}, \%request_parameters);

# disconnect database connections
$db{ykksm}->disconnect();
$db{ykval}->disconnect();

# send response to client
send_response("OK");
write_log("OK, counter=$request_parameters{counter} low=$request_parameters{low} high=$request_parameters{high} use=$request_parameters{use}");
close_log();

exit();



sub open_log{
	my $logfile = shift;
	open($LOG, '>>' , $logfile);
}

sub close_log{
    close($LOG);
}
sub write_log{
    my $msg = shift;
    print $LOG "$msg\n";
    
}

sub getUTCTimeStamp {
	$ENV{TZ} = "UTC";
	my $time = time;
	my $date = strftime '%Y-%m-%dT%H:%M:%SZ0', localtime $time;
	$date .= sprintf "%03d", ($time-int($time))*1000;
	return $date;
}

sub send_response{
	my $msg = shift;

	$response_header{status} = $msg;
	my $h=sign_response(%response_header);

#	client seems to be really picky with the order of these so we set them manually instead..
#	foreach my $key (sort keys %response_header){
#		print "$key=$response_header{$key}\n";
#	}
 
	my $response;
	$response  = "h=$h\n";
	$response .= "t=$response_header{t}\n";
	$response .= "otp=$response_header{otp}\n";
	$response .= "nonce=$response_header{nonce}\n";
	$response .= "sl=$response_header{sl}\n";
	$response .= "status=$response_header{status}\n";

	write_log("send_reponse:\n==========\n$response\n==========");
	print $response;
	exit;
}

sub update_db_counters{

	my $yubikey_id = shift;
	my $request_parameters = shift;

	my $sql_stm = "UPDATE yubikeys set yk_counter = '$request_parameters{counter}', yk_use = '$request_parameters{use}', yk_low = '$request_parameters{low}', yk_high = '$request_parameters{high}', nonce = '$request_parameters{nonce}' WHERE yk_publicname = '$yubikey_id'";

	write_log("Updating DB Counters: $sql_stm");
	$db{ykval}->do($sql_stm);

}

sub counters_higher{
	my $p1 = shift;
	my $p2 = shift;

	if($p1->{counter} > $p2->{counter} || ($p1->{counter} == $p2->{counter} && $p1->{use} > $p2->{use})){
		write_log("Server counters are higher than OTP, db_counter = $p1->{counter} otp_counter = $p2->{counter} db_use = $p1->{use} otp_use = $p2->{use}");
		return 1;
	}else{
		return 0;
    }
}

sub counters_higher_or_equal{
	my %rp = @_;
	if($db_data{counter} > $rp{counter} || ($db_data{counter} == $rp{counter} && $db_data{use} >= $rp{use})){
		write_log("REPLAYED_OTP: db_counter = $db_data{counter} otp_counter = $rp{counter} db_use = $db_data{use} otp_use = $rp{use}");
		return 1;
	}else{
		return 0;
	}
}

sub counters_equal{
	my %rp = @_;

	if($rp{counter} == $db_data{counter} && $rp{use} == $db_data{use}){
		write_log("REPLAYED_REQUEST: db_counter = $db_data{counter} otp_counter = $rp{counter} db_use = $db_data{use} otp_use = $rp{use}");
		return 1;
	}else{
		return 0;
	}
}

sub get_api_key{
	my $id = shift;
	my $stm = $db{ykval}->prepare("SELECT secret FROM clients WHERE id = '$id' and active = '1'");
	$stm->execute();
	if(my $ref = $stm->fetchrow_hashref()){
		$api_key = $ref->{secret};
	}else{
		write_log("Could not find secret for client \"$id\": SELECT secret FROM clients WHERE id = '$id' and active = '1'");
		send_response('NO_SUCH_CLIENT');
	}
}

sub get_yubikey_data_from_db{
	my $key_id = shift;

	my %data;
	$data{key_id} = $key_id;

	my $stm = $db{ykksm}->prepare("SELECT aeskey, internalname FROM yubikeys WHERE publicname = '$key_id' and active = 1");
	$stm->execute();
	if(my $ref = $stm->fetchrow_hashref()){
		$data{aes} = $ref->{'aeskey'};
		$data{internalname} = $ref->{'internalname'};
	}else{
		write_log("Yubikey($key_id) not found or inactive");
		send_response('active yubikey($key_id) not found in DB');
	}
	$stm->finish();

	$stm = $db{ykval}->prepare("SELECT yk_counter, yk_use, yk_low, yk_high, nonce FROM yubikeys WHERE yk_publicname = '$key_id' and active = 1");
	$stm->execute();
	if(my $ref = $stm->fetchrow_hashref()){
		$data{counter} = $ref->{'yk_counter'};
		$data{use} = $ref->{'yk_use'};
		$data{low} = $ref->{'yk_low'};
		$data{high} = $ref->{'yk_high'};
		$data{nonce} = $ref->{'nonce'};
	}else{
		write_log("Yubikey($key_id) not found or inactive");
		send_response('active yubikey($key_id) not found in DB');
	}
	$stm->finish();

	return %data;
}

sub connect_db{

	my %connections;
	$connections{ykksm} = DBI->connect("DBI:mysql:database=ykksm;host=localhost", "ykksmreader", "PASSWORD", {'RaiseError' => 1});
	$connections{ykval} = DBI->connect("DBI:mysql:database=ykval;host=localhost", "ykval_verifier", "PASSWORD",{'RaiseError' => 1});

	return %connections;
}

sub decrypt_yubikey{
	my %request = @_;

	my @matches = ($request{otp} =~ /^([cbdefghijklnrtuv]{0,16})([cbdefghijklnrtuv]{32})$/);
	my $id = $matches[0];
	my $modhex_chipertext = $matches[1];

	%db_data = get_yubikey_data_from_db($id);

	my $aes_key = $db_data{aes};
	my $internal_name = $db_data{internalname};

	if (!$aes_key) {
		write_log("AES key not found for $id");
		send_response("Unknown yubikey\n");
	}

	my $chipertext = modhex2hex($modhex_chipertext);
	my $plaintext = aes128ecb_decrypt($aes_key, $chipertext);

	return $plaintext;
}

sub extract_params{
	my $plaintext = shift;

	my %params;
	$params{counter} = hex("0x" . substr($plaintext, 14, 2) . substr($plaintext, 12, 2));
	$params{low} = hex("0x" . substr($plaintext, 18, 2) . substr($plaintext, 16, 2));
	$params{high} = hex("0x" . substr($plaintext, 20, 2));
	$params{use} = hex("0x" . substr($plaintext, 22, 2));
	write_log("OTP Data: counter = $params{counter}, low = $params{low}, high = $params{high}, use = $params{use}");
	return %params;
}

sub compare_uid_with_internalname{
	my $plaintext = shift;
	my $internal_name = shift;

	my $uid = substr($plaintext, 0, 12);
	write_log("Comparing UID($uid) with internalname($internal_name)");
	# if internal name is set it has to match $uid
	if($internal_name && $uid ne $internal_name){
		write_log("BAD_OTP: internalname($internal_name) does not match UID($uid)");
		send_response('BAD_OTP');
	}
}

sub translate_dvorak{
	my $otp = shift;
	if($otp =~ m/^[jxe.uidchtnbpygk]+$/){
		my %dvorak_translation = (j => 'c', x => 'b', e => 'd', '.' => 'e', u => 'f', i => 'g', d => 'h', c => 'i', h => 'j', t => 'k', n => 'l', b => 'n', p => 'r', y => 't', g => 'u', k => 'v');
		my $keys_regex =  map quotemeta, keys %dvorak_translation;
		$otp =~ s/($keys_regex)/$dvorak_translation{$1}/g;
		write_log("OTP translated from DVORAK");
	}
	return $otp;
}

sub modhex2hex{
	my $modhex = shift;
	my %modhex2hex_translation = (c => '0',b => '1',d => '2',e => '3',f => '4',g => '5',h => '6',i => '7',j => '8',k => '9',l => 'a',n => 'b',r => 'c',t => 'd',u => 'e',v => 'f');
	my $keys_regex = join '|', map quotemeta, keys %modhex2hex_translation;

	$modhex =~ s/($keys_regex)/$modhex2hex_translation{$1}/g; 
	return $modhex
}

sub hex2bin{
	my $hex = shift;
	my $return = "";
	my @hex_array = split(//, $hex);
	for(my $i=0; $i<(length $hex); $i+=2){
		$return = $return . chr(hex($hex_array[$i] . $hex_array[$i+1]));
	}
	return $return;
}

sub bin2hex{
	my $bin = shift;
	my $return = "";
    
	my $n = length($bin);
	my $s = 2*$n;
	$return = unpack("H$s", $bin);

	return $return;
}

sub aes128ecb_decrypt{
	my $aeskey = shift;
	my $chipertext = shift;
	my $iv = hex2bin('00000000000000000000000000000000');
	my $td = Mcrypt->new(algorithm => Mcrypt::RIJNDAEL_128(), mode => Mcrypt::ECB(), verbose   => 0, );
	$td->init( hex2bin($aeskey), $iv ) or die "Could not initialize td";
	my $decrypted = bin2hex($td->decrypt(hex2bin($chipertext)));
	$td->end();
	return $decrypted;
}

sub crc_is_good{
	my $token = shift;
	my $crc = calculate_crc($token);
	return $crc == 0xf0b8;
}

sub calculate_crc{
	my $token = shift;
	my @hex_array = split(//, $token);
	my $crc = 0xffff;

	for (my $i = 0; $i < 16; $i++ ) {
		my $b = hex("0x" . $hex_array[$i*2] . $hex_array[($i*2)+1]);
		$crc = $crc ^ ($b & 0xff);
		for (my $j = 0; $j < 8; $j++) {
			my $n = $crc & 1;
			$crc = $crc >> 1;
			if ($n != 0) {
				$crc = $crc ^ 0x8408;
			}
		}
	}
	return $crc;
}

sub check_client_signature{
	my %request = @_;
	my $content = "";

	if($request{h} ne ''){
		foreach my $key (sort keys %request) {
			next if($key eq "h");
			next if($key eq "timeout" && $request{timeout} eq '');
			next if($key eq "sl" && $request{sl} eq '');
			next if($key eq "timestamp" && $request{timestamp} eq '');
			next if($key eq "status");
			$content = $content."&$key=$request{$key}";    
		}
		$content = substr($content, 1);

		my $key = decode_base64($api_key);
		my $signature = encode_base64(hmac_sha1($content, $key), '');
		if($request{h} ne $signature){
			write_log("check_client_signature: mismatch, h=$request{h} and signature=$signature");
			send_response("BAD_SIGNATURE");
		}
	}
}

sub sign_response{
	my %response = @_;
	my $content = "";

	foreach my $key (sort keys %response) {
	next if($key eq "h");
		next if($key eq "timeout" && $response{timeout} eq '');
		next if($key eq "sl" && $response{sl} eq '');
		next if($key eq "timestamp" && $response{timestamp} eq '');
		$content = $content . "&$key=$response{$key}";
	}
	$content = substr($content, 1);
	my $key = decode_base64($api_key);
	my $signature = encode_base64(hmac_sha1($content, $key), '');

	return $signature;

}

sub check_request{
	my %request = @_;
	my $token_len = 32;
	my $otp_max_len = 48;

	if ($request{otp} eq '') {
		write_log("OTP is missing");
		send_response('OTP is missing');
	}

	if (length $request{otp} < $token_len || length $request{otp} > $otp_max_len) {
		write_log("Incorrect OTP length: ' . $otp");
		send_response('Incorrect OTP length: ' . $otp);
	}

	if ($request{otp} !~ m/^[cbdefghijklnrtuv]+$/) {
		write_log("Invalid OTP:  $otp");
		send_response("Invalid OTP:  $otp");
	}

	if ($request{id} !~ m/^[0-9]+$/){
		write_log("client id provided in request must be an integer");
		send_response('client id provided in request must be an integer');
	}

	if ($request{timeout} && $request{timeout} !~ m/^[0-9]+$/) {
		write_log("timeout is provided but not correct");
		send_response('timeout is provided but not correct');
	}

	if (!$request{nonce}){
		write_log("nonce is required");
		send_response('nonce is required');
	}
	if ($request{nonce} && $request{nonce} !~ m/^[A-Za-z0-9]+$/) {
		write_log("nonce is provided but not correct");
		send_response('nonce is provided but not correct');
	}

	if ($request{nonce} && ((length $request{nonce}) < 16 || (length $request{nonce}) > 40) ){
		write_log("nonce too short or too long");
		send_response('nonce too short or too long');
	}

	if ($request{sl} && ($request{sl} !~ m/^[0-9]+$/ || ($request{sl}<0 || $request{sl}>100))) {
		write_log("SL is provided but not correct");
		send_response('SL is provided but not correct');
	}

	if ($request{id} <= 0) {
		write_log("Client ID is missing");
		send_response('Client ID is missing');
	}

}
