#/bin/bash

# stop everything on SIGINT
trap 'exit' SIGINT


progs=(forkbomb/forkbomb_v1 forkbomb/forkbomb_v2 forkbomb/forkbomb_v3 forkbomb/forkbomb_v4 forkbomb/forkbomb_v5 forkbomb/benign_while mario/mario resize/resize vigenere/vigenere)
n=${#progs[@]}

RES=res.out

# clear existing redults file 
> $RES


# run each pair of programs against eachother
for ((i=0; i<$n; i++))
do 
    for ((j=i; j<$n; j++))
    do
        file1=${progs[i]}
        file2=${progs[j]}
        echo "${file1} ${file2}" | tee -a $RES
        #timeout --foreground 30 ./analyze_binary.py -g tests/$file1 tests/$file2 | tee /dev/tty | tail -n1 >> $RES
        timeout --foreground 30s ./analyze_binary.py -g tests/$file1 tests/$file2 | tail -n1 | tee -a $RES
        echo "" | tee -a  $RES
    done;
done 2> /dev/null

