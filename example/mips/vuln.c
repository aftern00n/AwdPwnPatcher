//mipsel-linux-gnu-gcc vuln.c -o vuln32_nopie
//mipsel-linux-gnu-gcc vuln.c -o vuln32_pie -fPIE -pie
//mips64el-linux-gnuabi64-gcc vuln.c -o vuln64 -fPIE -pie
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char content[] = "Please tell us your name: ";
char * book[10];

void init()
{
    char name[0x20];
	setvbuf(stdout, 0LL, 2, 0LL);
	setvbuf(stdin, 0LL, 1, 0LL);
	setvbuf(stderr, 0LL, 2, 0LL);
    puts(content);
    read(0, name, 0x100);

}

void menu(){
    puts("------------------------");
	puts("1: add. ");
	puts("2: delete. ");
	puts("3: show. ");
	puts("4: exit. ");
	puts("------------------------");
	printf("which command?\n> ");
}

int read_int()
{
	char buf[4];
	read(0,buf,4);
	return atoi(buf);
}

void add(){
    int index;
    char * ptr;
    puts("Please input index: ");
    index = read_int();
    if (index>=0 && index<10){
        puts("Please input book name: ");
        ptr = (char *)malloc(0x20);
        read(0, ptr, 0x20);
        book[index] = ptr;
    }
    else {
        puts("Invalid index!");
    }
    

}

void del(){
    int index;
    puts("Please input index: ");
    index = read_int();
    if (index>=0 && index<10){
        free(book[index]);
    }
    else {
        puts("Invalid index!");
    }
}

void show(){
    int index;
    puts("Please input index: ");
    index = read_int();
    printf(book[index]);

}

void bye_bye(){
    puts("bye bye~!");
    exit(0);
}

int main()
{
    init();
    while(1){
        int choose;
        menu();
        choose = read_int();
        switch(choose){
        case 1:
            add();
            break;
        case 2:
            del();
            break;
        case 3:
            show();
            break;
        case 4:
            bye_bye();
            break;
        default:
            break;
        }
    }
    return 0;
}
