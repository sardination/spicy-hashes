#include <unistd.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    // validate
    int height = atoi(argv[1]);

    if (height < 0 || height > 23) {
        return 1;
    }


    for (int i = 0; i < height; ++i) {
        for (int j = 0; j < height - i - 1; ++j) {
            write(1, " ", 1);
        }

        for (int k = 0; k < i + 2; ++k) {
            write(1, "#", 1);
        }

        write(1, "\n", 1);
    }
}
