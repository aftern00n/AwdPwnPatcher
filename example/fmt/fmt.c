//gcc fmt.c -o fmt64 -fno-builtin-printf
//gcc fmt.c -o fmt32_nopie -fno-builtin-printf -no-pie -m32
//gcc fmt.c -o fmt32_pie -fno-builtin-printf -m32
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
    char * p;
    p = (char *)malloc(0x40);
    read(0, p, 0x40);
    printf(p);
    return 0;
}

