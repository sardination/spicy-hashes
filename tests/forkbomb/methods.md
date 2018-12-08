# forkbomb_v1
* The base forkbomb malware

# forkbomb_v2
* Uses a useless variable and for loop before the forkbomb to obfuscate

# forkbomb_v3
* Same as v2 but
    * Makes uses a bogus if statement to go to the fork code
    * Adds a useless variable and for loop *after* the forkbomb loop to obfuscate
* Also trying to use `__attribute__(used)` option

# forkbomb_v4
* Same as v3 but now with nops everywhere
