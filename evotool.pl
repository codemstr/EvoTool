#!/usr/bin/perl
use strict;
use warnings;
use ExtUtils::testlib;
use EvoTool;
#######################################################
## sponji - EvoTool v1.0.3                           ##
## EvoTool module provides some C functions for ...  ##
## cracking 4x4 Evolution 1 & 2 IRC server passwords ##
#######################################################

#######################################################
## This tool should be used for your own IRC server  ##
## only. Or authorized to use it.                    ##
#######################################################

#######################################################
## Example usuage                                    ##
#######################################################

my $ip = $ARGV[0] || '192.168.254.28';
my $longip = longIp($ip);
my $port = $ARGV[1] || 55916;
my $challenge = $ARGV[2] || '4eee06f9';
print crypt($challenge, $challenge), "\n";

#my $ip = EvoTool::demangleNick($nick);
#EvoTool::Evo1Password($nick, $longip);
my $password;
my $pwdOk = 0;

my $nick = EvoTool::mangleNick($ip,$port);

#my $nick = EvoTool::mangleNick($ip,$port); #We create a nick out of our IP:PORT

if ($ARGV[2] && $challenge ne "") { 
    $password = EvoTool::Evo2Password($nick, $longip, $challenge); #Generate a valid password!
    $pwdOk = EvoTool::verifyPasswordEvo2($nick,$longip,$password,$challenge);
} else {
    $password = EvoTool::Evo1Password($nick,$longip);
    $pwdOk = EvoTool::verifyPasswordEvo1($nick,$longip,$password);
}

if ($pwdOk) {
    if (length($password) == 6) {
	print "Evo1 password: $password\n";
    	EvoTool::printfVerifyPasswordEvo1($nick,$longip,$password);
    } elsif (length($password) == 4) {
	print "Evo2 password: $password\n";
    	EvoTool::printfVerifyPasswordEvo2($nick,$longip,$password,$challenge);
    }
}

sub nicktoip {
    my $nick = shift;
    if (length($nick) == 12) {
          $nick =~ y/A-P/0-9A-F/;
          my $ip = sprintf "%vd:%d", unpack "A4n", pack "H*", $nick;
          return $ip;
    } else {
          return "Nick lenght not equal 12 chars long! $nick";
    }
}

sub iptonick {
    my $ip = unpack "H8", pack "C4n", split /[.:]/, $_[0];
    $ip =~ y/0-9a-f/A-P/;
    my $port = unpack "H4", pack "S4n", int ( rand ( 65534 )  );
    $port =~ y/0-9a-f/A-P/;
    my $ported = join '', $ip, $port;
    return $ported;
}

sub longIp {
   return unpack 'N!', pack 'C4', split /\./, shift;
}
