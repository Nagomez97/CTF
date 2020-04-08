#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]){

	if(strcmp(argv[1], "this is the flag") == 0){
		printf("Hooray!\n");
	}
	else {
		printf("Shame on you...\n");
	}

	return 0;
}