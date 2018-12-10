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
* Copied forkbomb_v4 code and assembled it ( gcc -O0 -S -c forkbomb_v5.c)
* Modified new assembly code:
    * Instruction substitution: Replacing instructions with other equivalent instructions. e.g.
        ```
        addl	$1, %eax
        subl	$-1, %eax
        ```
    * Unnecssary instruction insertion. Extra copies of:
        ```
        movq	%rsp, %rbp
        ```
        for example
* Used `gcc forkbomb_v5.s -o forkbomb_v5` to assemble modified binary

# benign
* Simple `hello world` looping program with a similar control flow to the forkbomb
* Tests our syscall heuristic
