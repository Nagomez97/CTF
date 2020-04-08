#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]){
	char c[10];
	c[0] = 't';
	c[1] = 'h';
	c[2] = 'e';
	c[3] = ' ';
	c[4] = 'f';
	c[5] = 'l';
	c[6] = 'a';
	c[7] = 'g';
	int i = 0;
	int flag = 0;

	for(i=0; i<8; i++){
		if(c[i] != argv[1][i]){
			flag=1;
		}
	}

	if(flag == 0){
		printf("Hooray!\n");
	}
	else {
		printf("Shame on you...\n");
	}

	return 0;
}