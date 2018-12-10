# Control Flow Based Malware Identification

## Installation

* We require Python 3.7 or higher and gcc to be installed
* We require `gcc-multilib` and `g++-multilib` to be installed
* Run `pip install -r requirements.txt` to install all python library requirements
* Install RetDec https://github.com/avast-tl/retdec
* Install Radare2 https://github.com/radare/radare2

## Runnning
* From the base directory run `python3 analyze.py -g <path1> <path2>` to
    compare the binaries at `<path1>` and `<path2>`
