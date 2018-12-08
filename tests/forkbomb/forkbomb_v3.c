#include <unistd.h>

int main()
{
    int a = 42;
    for (int i = 0; i < 10; ++i) {
        a += i;
    }
    if (a == 87) {
        while(1)
           fork();
        return 0;
        static int b __attribute__((used)) = 1;
        for (int j = 0; j < 10; ++j) {
            b += j;
        }
    }
    else {
        return 0;
    }
}
