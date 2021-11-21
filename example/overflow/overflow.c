//gcc overflow.c -o overflow64 -fno-stack-protector
//gcc overflow.c -o overflow32 -fno-stack-protector -no-pie -m32
#include <stdio.h>
#include <unistd.h>

int main()
{
    char a[32];
    read(0, a, 0x100);
    puts(a);
    return 0;
}

