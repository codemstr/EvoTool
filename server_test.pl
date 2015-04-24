#!/usr/bin/perl
use strict;
use warnings;
use IO::Socket::INET;
use Socket;

use ExtUtils::testlib;
use EvoTool;
#######################################################
## sponji - EvoTool v1.0.3                           ##
## EvoTool module provides some C functions for ...  ##
## cracking 4x4 Evolution 1 & 2 IRC server passwords ##
#######################################################
use constant DATAGRAM_MAXLEN => 1024;
my $EvoServer = '192.168.254.21';

my $ip = $ARGV[0] || '192.168.254.21';
my $longip = longIp($ip);
my $port = $ARGV[1] || int(rand(9999));

my $challenge = $ARGV[2] || undef;

#my $ip = EvoTool::demangleNick($nick);
#EvoTool::Evo1Password($nick, $longip);
my $password;
my $pwdOk = 0;

my $nick = EvoTool::mangleNick($ip,$port); #We create a nick out of our IP:PORT

if ($ARGV[2] && $challenge ne "") { 
    #$password = EvoTool::Evo2Password($nick, $longip, $challenge); #Generate a valid password!
    #$pwdOk = EvoTool::verifyPasswordEvo2($nick,$longip,$password,$challenge);
} else {
    #$password = EvoTool::Evo1Password($nick,$longip);
    #$pwdOk = EvoTool::verifyPasswordEvo1($nick,$longip,$password);
}

if ($pwdOk) {
    if (length($password) == 6) {
	#print "Evo1 password: $password\n";
    	EvoTool::printfVerifyPasswordEvo1($nick,$longip,$password);
    } elsif (length($password) == 4) {
	#print "Evo2 password: $password\n";
    	EvoTool::printfVerifyPasswordEvo2($nick,$longip,$password,$challenge);
    }
}


#########SERVER TESTING###########
my ($client_socket,$request);
my ($peer_address,$peer_port);

my $socket = IO::Socket::INET->new(
	PeerAddr  => $EvoServer,
	PeerPort  => '6667',
        Type      => SOCK_STREAM,
	Proto     => 'tcp') || die "$!\n";


print $socket "USRIP\n";
while (my $answer = <$socket>) {
    if ($answer =~ /unknown=\+unknown\@(.*)/) {
	$ip = $1;
	$longip = longIp($ip);
	$nick = EvoTool::mangleNick($ip,$port);

    } elsif ($answer =~ /CHALLENGE (.*)/) {
	$challenge = $1;
	$password =  EvoTool::Evo2Password($nick, $longip, $challenge);
	print $socket "PASS $password\n";
	print $socket "NICK $nick\n";
	print $socket "USER 00000000.4x4evo1-english-pc-124 127.0.0.1 192.168.254.21 :rPi_$port^0\n";
    } 
     if ($answer =~ /(.*) 376 $nick/) {
	print $socket "JOIN #revo\n";
        print $socket "RCHG rPi_$port^0\n";
	#print $socket "PRIVMSG #revo :Hello, all your base belongs to me!\n";
    }
    if ($answer =~ /PING :(.*)/) {
        print $socket "PONG :$1\n";
    }
    #print "$answer\n";
}

sub longIp {
   return unpack 'N!', pack 'C4', split /\./, shift;
}
