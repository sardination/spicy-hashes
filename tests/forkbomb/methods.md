# forkbomb_v1
* The base forkbomb malware

# forkbomb_v2
* Uses a useless variable and for loop before the forkbomb to obfuscate

# forkbomb_v3
* Same as v2 but
    * Makes use of a bogus if statement to go to the fork code
    * Adds a useless variable and for loop *after* the forkbomb loop to obfuscate
* Also trying to use `__attribute__(used)` option

# forkbomb_v4
* Same as v3 but now with nops everywhere

# forkbomb_v5
* Took forkbomb_v4 binary and disassembled it
* Modified new assembly code:
    * Instruction substitution: Replacing instructions with other equivalent
        instructions. e.g.
        ```
         100000fa3:	83 c0 01 	addl	$1, %eax
         100000fa3:	83 c0 01 	subl	$-1, %eax
        ```
* Used `as` to re-assemble newly modified binary



* TODO: benign programs that look similar to the malware
