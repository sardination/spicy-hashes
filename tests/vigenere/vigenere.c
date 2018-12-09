#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define ALPHASIZ 26
#define PLAINSZ 2048

int main(int argc, char **argv) {
    // usage
    if (argc != 2) {
        return 1;
    }

    // get keyword, keyindex, and keylen
    char *key = argv[1];
    int keyi = 0;
    int keyn = strlen(key);

    // process key chars into shifts.  reject if nonalpha
    for (int i = 0; i < keyn; i++) {
        if (!isalpha(key[i])) {
            return 2;
        }
        key[i] = toupper(key[i]) - 'A';
    }

    // get plaintext
	char plain[PLAINSZ];
    int n = read(0, plain, PLAINSZ) - 1;
    //int n = strlen(plain);

    // print scrambled
    for (int i = 0; i < n; ++i) {
        if (isupper(plain[i]))
            plain[i] = ((plain[i] - 'A' + key[keyi++ % keyn]) % ALPHASIZ) + 'A';
        else if (islower(plain[i]))
            plain[i] = ((plain[i] - 'a' + key[keyi++ % keyn]) % ALPHASIZ) + 'a';
        else
            plain[i] = plain[i];

    }

	write(1, plain, n + 1);

    return 0;
}

