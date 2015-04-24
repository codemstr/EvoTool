#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"
#include "netircpw.h"


MODULE = EvoTool		PACKAGE = EvoTool		

SV *
demangleNick(char *nick) 
   CODE:
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
      // printf("%d.%d.%d.%d:%d\n",a1, a2, a3, a4, port);
      char buf[120];
      sscanf(buf,"%d.%d.%d.%d:%d",a1, a2, a3, a4, port);
      RETVAL = newSVpv(buf, 0);
   OUTPUT:
      RETVAL

SV *
mangleNick(char *addr, char *port)
  CODE:
    char buff[13];
    int a1, a2, a3, a4;
    int io1, io2, io3, io4, ioport;
    char o1[4], o2[4], o3[4], o4[4], oport[4];
    sscanf(addr, "%4[^.].%4[^.].%4[^.].%4[^.]", o1, o2, o3, o4);
    io1 = atoi(o1);
    io2 = atoi(o2);
    io3 = atoi(o3);
    io4 = atoi(o4);
    ioport = atoi(port);
    printAlphaHex(addr, io1 , 2);
    printAlphaHex(addr+2, io2, 2);
    printAlphaHex(addr+4, io3, 2);
    printAlphaHex(addr+6, io4, 2);
    printAlphaHex(addr+8, ioport, 4);
    addr[12] = '\0'; //chop it off at 12 chars
    RETVAL = newSVpv(addr, 0);
    //printf("%s\n", addr);
  OUTPUT:
    RETVAL

SV *
Evo1Password(char *nick, char *usrIp)
  CODE:
    char password[6];
    static unsigned UsrIp;
    sscanf(usrIp, "%d", &UsrIp);
    generateNickPassword(nick, UsrIp, password);
    RETVAL = newSVpv(password, 0);
    //printf("%s\n", password);
  OUTPUT:
    RETVAL

SV *
Evo2Password(const char *nick, char *usrIp, char *challenge)
  CODE:
    //sponji my badass hacking skills
    char result[4];
    static unsigned Challenge;
    static unsigned UsrIp;
    char Nick[12];
    sscanf(nick, "%s", &Nick);
    sscanf(usrIp, "%d", &UsrIp);
    sscanf(challenge, "%x", &Challenge);
    computeNickPasswordCheckSum(Nick, UsrIp, Challenge, result);
    RETVAL = newSVpv(result, 0);
    //return(result);
    //printf("%s\n", result);
  OUTPUT:
    RETVAL

SV *
verifyPasswordEvo2(char *nick, char *usrIp, char *pass, char *challenge)
    CODE:
    //sponji Evo2 password cracking
    static unsigned Challenge;
    static unsigned LongIp;
    sscanf(usrIp, "%d", &LongIp);
    sscanf(challenge, "%x", &Challenge);
    int pwdOk = verifyNickPasswordEvo2(nick, LongIp, pass, Challenge);
    if (pwdOk > 0) {
         return pwdOk;
    } else {
      	 return pwdOk;
    }

SV *
verifyPasswordEvo1(char *nick, char *usrIp, char *pass)
    CODE:
    //sponji Evo password cracking
    static unsigned LongIp;
    sscanf(usrIp, "%d", &LongIp);
    int pwdOk = verifyNickPasswordEvo1(nick, LongIp, pass);
    if (pwdOk > 0) {
       return pwdOk;
    } else {
      return pwdOk;
    }


void printfVerifyPasswordEvo2(char *nick, char *usrIp, char *pass, char *challenge)
    CODE:
    //sponji Evo2 password cracking
    static unsigned Challenge;
    static unsigned LongIp;
    sscanf(usrIp, "%d", &LongIp);
    sscanf(challenge, "%x", &Challenge);
    int pwdOk = verifyNickPasswordEvo2(nick, LongIp, pass, Challenge);
    if (pwdOk == 1) {
       printf("Verified password and challenge OK!\n");
    } else {
       printf("Verification of password and challenge failed: %d ", pwdOk);
       printf("%s\n", verifyNickPasswordMsg);
    }

void printfVerifyPasswordEvo1(char *nick, char *usrIp, char *pass)
    CODE:
    //sponji Evo password cracking
    static unsigned LongIp;
    sscanf(usrIp, "%d", &LongIp);
    int pwdOk = verifyNickPasswordEvo1(nick, LongIp, pass);
    if (pwdOk == 1) {
       printf("Verified password OK!\n");
    } else {
       printf("Verification failed %d ", pwdOk);
       printf("%s\n", verifyNickPasswordMsg);
    }
