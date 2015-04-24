/*
 * Made by sponji 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <strings.h>
#include <assert.h> 
#include "netircpw.h"


static unsigned Challenge;
static unsigned LongIP;
static const char* Nick;
static const char* Pass;

char myIrcNick[13]; 

//First public release, 2012 June 9th 1:45PM

//sponji convert evo nick into IP

int demangleNick(char *nick) {
        // Parse out IP and port from nick
        int a1 = parseAlphaHex(nick, 2);
        int a2 = parseAlphaHex(nick+2, 2);
        int a3 = parseAlphaHex(nick+4, 2);
        int a4 = parseAlphaHex(nick+6, 2);
        int port = parseAlphaHex(nick+8, 4);
        if (
                (a1 < 0) || (a1 > 255) ||
                (a2 < 0) || (a2 > 255) ||
                (a3 < 0) || (a3 > 255) ||
                (a4 < 0) || (a4 > 255) ||
                (port < 1) || (port > 65535)
        ) {
                return 0;
        }
        // OK
	printf("%d.%d.%d.%d:%d\n",a1, a2, a3, a4, port);
}
//char getValues(int *a1, int *a2, int *a3, int *a4);
 // o1 - o4 are the octets in decimal as a string // char o1[5], o2[5], o3[5], o4[5]; // int io1, io2, io3, io4; //integer value of the octets 
// int n1, n2, n3, n4; //integer values of the nick // int port; 

//integer value for port from NICK 
//sponji - convert IP and Port into NICK 

void mangleNick(char *addr, char *port) {
        int a1, a2, a3, a4;
	int p = 9999;
        int io1, io2, io3, io4, ioport;
        char o1[4], o2[4], o3[4], o4[4], oport[4];
	sscanf(addr, "%4[^.].%4[^.].%4[^.].%4[^.]", o1, o2, o3, o4);
	//printf("%d %d %d %d %d\n", o1, o2, o3, o4, port);
	//getValues(&a1, &a2, &a3, &a4);
	io1 = atoi(o1);
        io2 = atoi(o2);
        io3 = atoi(o3);
        io4 = atoi(o4);
        ioport = atoi(port);
	//printf("%d %d %d %d %d\n", io1, io2, io3, io4, ioport);
	//printf("%s\n", addr );
        printAlphaHex2(addr, io1 , 2);
        printAlphaHex2(addr+2, io2, 2);
        printAlphaHex2(addr+4, io3, 2);
        printAlphaHex2(addr+6, io4, 2);
        printAlphaHex2(addr+8, ioport, 4);
	//printf("%s\n", addr );
	addr[12] = '\0';
	printf("%s\n", addr);
}
int printAlphaHex2(char *buf, unsigned value, int digits) {
        int i;
        for (i = 0 ; i < digits ; ++i) {
                unsigned digValue = (value >> (unsigned)((digits - i - 1)*4)) & 0xf;
                buf[i] = 'A' + digValue;
        }
// assert(parseAlphaHex(buf, digits) == value); // return 1;
}

void computeNickPasswordCheckSum2(const char nick[12], unsigned usrIp, unsigned randomVal, char *result) {
        int rounds, i, j;
        unsigned r = usrIp;
        for (rounds = 0 ; rounds < 10 ; ++rounds) {
                for (i = 0 ; i < 12 ; ++i) {
                        unsigned c = nick[i];
                        r ^= c << 24;
                        r ^= randomVal;
                        for (j = 0 ; j < 8 ; ++j) {
                                if (r & 0x80000000) {
                                        r = (r << 1U) ^ 0xa67f3443;
                                } else {
                                        r = (r << 1U) ^ 0x378624e5;
                                }
                        }
                        r += c;
                }
        }
        r &= 0xffff;
	printAlphaHex(result, r, 4);
        result[4] = '\0';
}
 
int main(int argc, char **argv) {
     int m, n, /* Loop counters. */
         l, /* String length. */
         x, /* Exit code. */
         ch; /* Character buffer. */
     char s[256]; /* String buffer. */
     for( n = 1; n < argc; n++ ) /* Scan through args. */
     {
       switch( (int)argv[n][0] ) /* Check for option character. */
       {
       case '+':
       case '/': x = 0; /* Bail out if 1. */
                 l = strlen( argv[n] );
                 for( m = 1; m < l; ++m ) /* Scan through options. */
                 {
                   ch = (int)argv[n][m];
                   switch( ch )
                   {
		   char password[20];
                   case 'h': printf("Syntax: %s [+h (This Help)] [+V (Version)] [+1 <NICK> <LONPIP> (Evo1 Password Generator] [+2 <NICK> <LONGIP> <CHALLENGE> (Evo2 Password Generator)] [+m <IP> (Mangle IP to NICK)] [+d <EVO NICK> (Demangle Nick to IP)] [+f <NICK> <LONGIP> <PASS> (Evo1 Password Verification)] [+v <NICK> <LONGIP> <PASS> <CHALLENGE> (Evo2 Password & Challenge Verification)]\n", argv[0]);
		   break;
                   case 'V': printf("Version 2.0.5-b - 4x4 Evolution authenication tools by sponji@mindboggle.us\n");
		   break;
		   case '1': if (argc == 4 && strlen(argv[2]) == 12 || strlen(argv[2]) == 13) {
				char password[20];
				sscanf(argv[3], "%d", &LongIP);
				generateNickPassword(argv[2], LongIP, password);
			       	printf("%s\n", password);
			      } else {
				    printf("Invalid options, try again.\n");
				}
		   break;
		   case '2': if (argc == 5) { 
				 char result[4];
				 sscanf(argv[3], "%d", &LongIP);
				 sscanf(argv[4], "%x", &Challenge);
                	         computeNickPasswordCheckSum(argv[2], LongIP, Challenge, result);
					printf("%s\n", result);
                               } else {
					printf("Invalid argument count %d != 5\n", argc);
				}
		   break;
		   case 'd': if (argc == 3 && strlen(argv[2]) == 12) {
             			 demangleNick(argv[2]);
			       }
		    break;
		    case 'm': if (argc == 4) {
				 	mangleNick(argv[2], argv[3]);
				} else {
				 	printf("Invalid argument count %d != 4\n", argc);
				 	return;
				}
			break; 
		   case 'v':
                               
				sscanf(argv[3], "%d", &LongIP);
				sscanf(argv[5], "%x", &Challenge);  
				verifyNickPasswordEvo2(argv[2], LongIP, argv[4], Challenge);
                         		printf("%s\n", verifyNickPasswordMsg);
				int pwdOk = verifyNickPasswordEvo2(argv[2], LongIP, argv[4], Challenge);     
				if (pwdOk == 1) {
                                        printf("Password OK : %d\n", pwdOk);
                                } else {
                                        printf("Password Failed %d\n", pwdOk);
                                }

		   break;
		   case 'f': if (argc == 5) {
			char password[20];
				}
			sscanf(argv[3], "%d", &LongIP);
			
	 		verifyNickPasswordEvo1(argv[2], LongIP, argv[4]);
			 printf("%s\n", verifyNickPasswordMsg);
		   break;
		   }
		  }
	}
      }
}
