/* Who knows? */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "compatibility.h"
#include "digest_md4.h"
#include "digest_md5.h"
#include "digest_rmd160.h"
#include "digest_sha1.h"

int main(int argc, char *argv[])
{
  char buffer[100];

  if (argc == 2) {
     MD4DataBase64((unsigned char *) argv[1],strlen(argv[1]),buffer,sizeof(buffer));
     printf("{MD4}%s\n",buffer);

     MD5DataBase64((unsigned char *) argv[1],strlen(argv[1]),buffer,sizeof(buffer));
     printf("{MD5}%s\n",buffer);

     RMD160DataBase64((unsigned char *) argv[1],strlen(argv[1]),buffer,sizeof(buffer));
     printf("{RMD160}%s\n",buffer);

     SHA1DataBase64((unsigned char *) argv[1],strlen(argv[1]),buffer,sizeof(buffer));
     printf("{SHA}%s\n",buffer);

     exit(0);
   } else {
     printf("Only one Parameter\n");
     exit(1);
   }
}
