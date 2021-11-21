//gcc fmt.c -o uaf64
//gcc fmt.c -o uaf32 -no-pie -m32
#include <stdio.h>
#include <stdlib.h>

void * p[10];

int main()
{
    unsigned int index;
    printf("Input index: ");
    scanf("%u", &index);
    if(index<10){
        p[index] = malloc(0x40);
        free(p[index]);
    }
    return 0;
}

