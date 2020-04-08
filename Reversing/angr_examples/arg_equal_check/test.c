#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

int main(int argc, char* argv[]){
	if(atoi(argv[1]) == 10){
		printf("Here is the flag.\n");
	}
	else{
		printf("Arg %d\n", atoi(argv[1]));
		printf("Oops not here.\n");
	}
	return 0;
}
