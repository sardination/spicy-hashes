#include<stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

int main() 
{
    int fd = open("test.txt", O_RDONLY | O_CREAT);
    for (int i = 0; i < 10; ++i) {
        int x = i;
    }

    if (fd == -1) { 
        printf("ERROR\n");
        exit(1);
    } 
    char buf[1024];
    int sz = read(fd, buf, 512); 
    return sz;
} 

