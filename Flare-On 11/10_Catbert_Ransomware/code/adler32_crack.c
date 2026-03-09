#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const unsigned int MOD_ADLER = 65521;

unsigned int adler32(unsigned char *data, size_t len) 
/* 
    where data is the location of the data in physical memory and 
    len is the length of the data in bytes 
*/
{
    unsigned int a = 1, b = 0;
    size_t index;
    
    // Process each byte of the data in order
    for (index = 0; index < len; ++index)
    {
        a = (a + data[index]) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    
    return (b << 16) | a;
}

int main(int argc, char **argv, char **envp) {
    // test
    char *test = "89ABCDEF";
    unsigned int sum = 0;
    sum = adler32(test, strlen(test));
    printf("adler32(\"%s\")=0x%x\n", test, sum);
    // brute?
    char *alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@ ";
    char string[8];
    int len = strlen(alpha);
    for (char a=0; a<len; a++) {
      for (char b=0; b<len; b++) {
        for (char c=0; c<len; c++) {
          for (char d=0; d<len; d++) {
            for (char e=0; e<len; e++) {
              for (char f=0; f<len; f++) {
                for (char g=0; g<len; g++) {
                  for (char h=0; h<len; h++) {
		    string[0] = a;
		    string[1] = b;
		    string[2] = c;
		    string[3] = d;
		    string[4] = e;
		    string[5] = f;
		    string[6] = g;
		    string[7] = h;
		    sum = adler32(string, 8);
		    if (sum == 0xf910374) {
		      printf("[+] Found string %s with target hash\n");
		      return(EXIT_SUCCESS);
		    }
		  }
		}
	      }
	    }
	  }
	}
      }
    }
    return(EXIT_SUCCESS);
}

