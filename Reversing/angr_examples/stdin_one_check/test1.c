#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(){
	char input[30];

	fgets(input, 30, stdin);

	if(strcmp(input, "this is the flag\n") == 0){
		printf("Hooray!\n");
	}
	else {
		printf("Shame on you...\n");
	}

	return 0;
}