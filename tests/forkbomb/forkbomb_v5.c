#include <unistd.h>

int main()
{
    asm ("nop");
    int a = 42;
    asm ("nop");
    for (int i = 0; i < 10; ++i) {
        asm ("nop");
        a += i;
        asm ("nop");
    }
    asm ("nop");
    while(1)
       fork();
    asm ("nop");
    return 0;
    asm ("nop");
    static int b __attribute__((used)) = 1;
    asm ("nop");
    for (int j = 0; j < 10; ++j) {
        asm ("nop");
        b += j;
        asm ("nop");
    }
    asm ("nop");
}

