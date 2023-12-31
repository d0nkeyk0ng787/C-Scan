# C-Scan

### Description

Port scanner written in C that can also grab the banner of the target service and do some basic OS fingerprinting. This is my solution to questions 2, 3 and 4 of [@eversinc33](https://twitter.com/eversinc33) **Red Team Advent of Code** found [here.](https://github.com/eversinc33/Red-Team-Advent-of-Code)

In an endeavour to better learn C and in particular how to interact and use the Win32 API, I am doing some of the challenges in this repo as a stepping stone to being able to create some of my own tools which can be used in red teamining engagements.

### Usage

Compile with the following command:
```cmd
gcc .\main.c -o scanner.exe -lws2_32 -lmswsock
```

Help menu:
```cmd
[!] Ensure you include the target IP address when executing the tool.
[!] Example Usage: .\scanner.exe 192.168.1.1
[!] Optional arguments (after IP address)
[!] -b | Banner Grabbing
[!] -O | OS Detection
[!] -h | Print this menu again
```