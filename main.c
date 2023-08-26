#include <stdio.h>
#include <Winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

int getOS(char * address);
int testPort(int port, char * address, int timeoutMillis, int grabBannerEnabled);
void grabBanner(int sockfd);
void startMessage();
void helpMenu();

int main(int argc, char *argv[]) {
    // Checking to make sure the required number of system arguments (2) is met or if the -h argument is used
    if (argc < 2) {
        helpMenu();
        return 1;
    } else if (argc == 2 && strcmp(argv[1],"-h") == 0) {
        helpMenu();
        return 1;
    }

    // Creating a WSADATA structure named wsa
    WSADATA wsa;

    // Initialise winsock library with WSAStartup. This takes 2 parameters. The first is the version, the second is the WSA struct
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0){
        printf("[-] WinSock initialisation failure.\n");
        return 1;
    }

    // We create a pointer of type FILE and store the top-1000-ports.txt file in read only mode
    FILE *filePointer = fopen(".\\top-1000-ports.txt", "r");

    // We check to make sure the filepointer pointer is not NULL, if it is we print the error message and exit the program
    if (filePointer == NULL) {
        perror("[-] Unable to open the ports file.\n");
        return 1;
    }

    // We create an int array of size 1000 to store the ports in, and the iterator i
    int ports[1000];
    int i;

    // We use a for loop and the fscanf function to read in as integers the lines from the file and place them in an array
    for (i = 0; i < 1000; i++) {
        fscanf(filePointer, "%d", &ports[i]);
    }

    // Print the start message
    startMessage();
    // Record the starting time
    clock_t start = clock();
    // Create an integer variable to store the scan result
    int scanResult;

    // Int variable to store whether -b is present or not
    int grabBannerEnabled;

    // Logic to determine whether to grab the banner or not
    if (argc > 2 && strcmp(argv[2],"-b") == 0) {
        grabBannerEnabled = 1;
    } else {
        grabBannerEnabled = 0;
    }

    // Check if -O is present
    if (argc > 2 && strcmp(argv[2], "-O") == 0) {
        getOS(argv[1]);
    } else if (argc > 3 && strcmp(argv[3], "-O") == 0) {
        getOS(argv[1]);
    }

    // Loop through the array of ports and run the testPort function for each, printing if it succeeded
    for (i = 0; i < 1000; i++){
        // Let scanResult be equal to the returned value of the testPort function
        scanResult = testPort(ports[i], argv[1], 1000, grabBannerEnabled);

        // Checking the value of scanResult and if its not 0 (so if the connection failed) print the host is not alive and end the program
        if (scanResult != 0) {
            //printf("%d is not alive on host %s\n", ports[i], argv[1]);
            continue;
        } else {
            // Continue
            continue;
        }
    }

    // Close the file
    fclose(filePointer);
    // Do a WSACleanup
    WSACleanup();
    
    // Record the end time
    clock_t end = clock();
    // Calculate the elapsed time and print how long the scan took to complete.
    double elapsedTime = ((double)(end - start) / CLOCKS_PER_SEC) / 60;
    printf("[!] The scan took %f minutes to complete.\n", elapsedTime);

    return 0;
}

int getOS(char * address) {
    // Create a handle variable to store the handle of the current process
    HANDLE hReadPipe, hWritePipe;
    // Create STARTUPINFOW, PROCESS_INFORMATION & SECURITY_ATTRIBUTE Structs
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa;
    // Create a buffer to store the stdout
    char buffer[4096];
    // Create a char array of the substring
    char subString[20] = "TTL=";
    // Create a char array to store the return TTL= string
    char *ret;
    // Create a DWORD for maximum number of bytes to read
    DWORD bytesRead;
    // Create DWORD to store the exit code of the child process
    DWORD exitCode;
    // Create part of the command
    char command[20] = "ping -n 2 ";
    // Append the IP to the command
    strcat(command, address);
    // Create a wchar_t array to store the wide version of the command
    wchar_t wCommand[40];
    // Convert the command to a wide string
    mbstowcs(wCommand, command, sizeof(wCommand));

    // Set the sa length to the length of SECURITY_ATTRIBUTES
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    // Set the SA struct to set the returned handle to be inherited when the process is created
    sa.bInheritHandle = TRUE;
    // Set the security descriptor pointer to NULL
    sa.lpSecurityDescriptor = NULL;
    // Create the pipe with the read and write pipes. Supply the secuirty_attributes struct and give a length of 0
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        printf("[-] Failed to create pipe.\n");
        return 1;
    }

    // Reserve memory block for si
    ZeroMemory(&si, sizeof(si));
    // Set the STARTUPINFO size of structure variable cb to the sizeof si
    si.cb = sizeof(si);
    // Set the StdInput to NULL
    si.hStdInput = NULL;
    // Set StdError & StdOutput to the Write side of the pipe
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    // Set the dwFlags to use STD Input, Output, Error Handles
    si.dwFlags |= STARTF_USESTDHANDLES;
    // Reserve memory block for pi
    ZeroMemory(&pi, sizeof(pi));
    
    // Create the process
    CreateProcessW(NULL, wCommand, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

    // Close the WritePipe handle
    CloseHandle(hWritePipe);

    // Create a start time using the systems up time clock
    DWORD startTime = GetTickCount();

    // Create char array of size 8 to store the extracted TTL
    char extractedString[8];

    // Ensure that the child process has finished its task
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    // While time time is less than 5000 miliseconds (5 seconds)
    while ((GetTickCount() - startTime) < 5000) {
        if (ReadFile(hReadPipe, &buffer, sizeof(buffer), &bytesRead, NULL)) {
            // If there are bytes in the buffer
            if (bytesRead > 0) {
                // Do nothing
                // Let ret equal the extracted substring (TTL=) from the buffer 
                ret = strstr(buffer, subString);
                // Verify that ret isn't NULL (avoid NULL pointer dereference)
                if (ret != NULL) {
                    // Copy the first 7 bytes of ret into extarctedString
                    strncpy(extractedString, ret, 7);
                    // Let the 7th byte of extractedString equal a NULL terminator
                    extractedString[7] = '\0';
                    //printf("%s\n", extractedString);
                    break; 
                } else {
                    // Do Nothing, keep trying!!!
                }   
            } else {
                // Error!
                break;
            }
        } else {
            // Do nothing
        }
    }

    // Close the hReadPipe handle
    CloseHandle(hReadPipe);

    // Close process thread and handle
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // First we convert the TTL value from char to int
    int numOne = extractedString[4] - '0';
    int numTwo = extractedString[5] - '0';
    int numThree = extractedString[6] - '0';
    
    // Check if the "third" TTL digit is really a carriage return as is the case for a 2 digit TTL
    if ((int)extractedString[6] == 13) {
        // Combine the TTL 
        int ttl = numOne * 10 + numTwo;
        // Check if the TTL falls between the range of 65-34
        if (ttl <= 64 && ttl >= 35) {
            printf("[+] Target is likely a Linux host!\n\n");
        } else {
            printf("[-] Unable to determine OS of target!\n\n");
        }
    } else {
        // Combine the TTL
        int ttl = numOne * 100 + numTwo * 10 + numThree;
        // Check if the TTL falls between the range of 129-98
        if (ttl <= 128 && ttl >= 99) {
            printf("[+] Target is likely a Windows host!\n\n");
        } else {
            printf("[-] Unable to determine OS of target!\n\n");
        }
    } 

    // Get the exit code of the process
    GetExitCodeProcess(pi.hProcess, &exitCode);

    return exitCode;
}

int testPort(int port, char * address, int timeoutMillis, int grabBannerEnabled) {
    
    // Creating an integer variable and setting it equal to 0
    int isOnline = 0;
    // Creating a struct named target_address of type sockaddr_in
    struct sockaddr_in target_address;
    // Creating an int variable to store the result of setting the I/O mode of the socket
    int iResult;
    // Creating an unsigned long to store the blocking mode, in this case 1 for non-blocking
    unsigned long iMode = 1;
    // Creating an integer variable to hold the result of select
    int selectResult;
    //int recvbuflen = 2048;
    // Store the receieved data

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    // Setting up the sockaddr_in struct
    target_address.sin_family = AF_INET;
    target_address.sin_port = htons(port); 
    target_address.sin_addr.s_addr = inet_addr(address);

    // Set the blocking mode to non-blocking and verifying no error
    iResult = ioctlsocket(sockfd, FIONBIO, (unsigned long *)&iMode);
    if (iResult == SOCKET_ERROR) {
        printf("[-] Failed to put the socket in non-blocking mode: %ld\n", iResult);
        printf("%d\n", WSAGetLastError());
    }

    // Create a timeval struct to hold the timeout period
    struct timeval timeout;
    timeout.tv_sec = timeoutMillis / 1000;
    timeout.tv_usec = (timeoutMillis % 1000) * 1000;
    
    // Attempting to connect to the target, checking if the result is a SOCKET_ERROR
    if(connect(sockfd, (struct sockaddr*)&target_address, sizeof(target_address)) == SOCKET_ERROR) {
        // Check if the error is a WSAEWOULDBLOCK error, indicating non-blocking connect in process
        if(WSAGetLastError() != WSAEWOULDBLOCK) {
            closesocket(sockfd);
            return 1;
        }

        // We use select() to wait for a connection or timeout, for this we need the fd_set structure, using writeFDs which is checking the socket for writability
        fd_set writeFds;
        // Initialises the set to the empty set. A set should always be cleared before use.
        FD_ZERO(&writeFds);
        // Place the socket sockfd into a set
        FD_SET(sockfd, &writeFds);

        // Set the selectResult equal to the result of running select() against our socket
        int selectResult = select(0, NULL, &writeFds, NULL, &timeout);

        // Check the result to see if the socket timed out. The select() function returns the total number of socket handles that are ready and contained in the
        // fd_set structures, zero if the time limit exceeded, or SOCKET_ERROR if an error occurred.
        if (selectResult <= 0 || !FD_ISSET(sockfd, &writeFds)) {
            closesocket(sockfd);
            return 1;
        }
    }

    printf("[+] Port %d is alive on host %s\n", port, address);

    // Grab banner here
    if (grabBannerEnabled == 1) {
        grabBanner(sockfd);
    }

    // Close the socket file descriptor
    closesocket(sockfd);

    // If the connection succeeded, return 0
    return 0;
}

void grabBanner(int sockfd) {

    int iResult;
    // Mode 0 = blocking
    unsigned long iMode2 = 0;
    // Create integer variable to store the recv result for checking
    int recvResult;
    // Store the bytes sent to us
    char recvBuf[2048] = {0};

    // Setting the socket back to blocking mode
    iResult = ioctlsocket(sockfd, FIONBIO, (unsigned long *)&iMode2);

    //connectTwo = connect(sockfd, (struct sockaddr*)&target_address, sizeof(target_address));
    // Receieve whatever the host is sending us
    recvResult = recv(sockfd, recvBuf, 2048, 0);

    if (recvResult > 0) {
        printf("[+] Service: %s\n", recvBuf);
    } else if (recvResult == 0) {
        printf("[-] Unable to grab service banner\n\n");
    } else {
        printf("[-] Recv failed %d\n\n", WSAGetLastError());
    }
}

void helpMenu() {
        printf("[!] Ensure you include the target IP address when executing the tool.\n");
        printf("[!] Example Usage: .\\scanner.exe 192.168.1.1\n");
        printf("[!] Optional arguments (after IP address)\n");
        printf("[!] -b | Banner Grabbing\n");
        printf("[!] -O | OS Detection\n");
        printf("[!] -h | Print this menu again\n");
}

void startMessage() {
    printf("[+] Welcome to d0nkeyk0ng's port scanner!\n");
    printf(R"EOF(         _          __________                              _,
     _.-(_)._     ."          ".      .--""--.          _.-{__}-._
   .'________'.   | .--------. |    .'        '.      .:-'`____`'-:.
  [____________] /` |________| `\  /   .'``'.   \    /_.-"`_  _`"-._\
  /  / .\/. \  \|  / / .\/. \ \  ||  .'/.\/.\'.  |  /`   / .\/. \   `\
  |  \__/\__/  |\_/  \__/\__/  \_/|  : |_/\_| ;  |  |    \__/\__/    |
  \            /  \            /   \ '.\    /.' / .-\                /-.
  /'._  --  _.'\  /'._  --  _.'\   /'. `'--'` .'\/   '._-.__--__.-_.'   \
 /_   `""""`   _\/_   `""""`   _\ /_  `-./\.-'  _\'.    `""""""""`    .'`\
(__/    '|    \ _)_|           |_)_/            \__)|        '       |   |
  |_____'|_____|   \__________/   |              |;`_________'________`;-'
   '----------'    '----------'   '--------------'`--------------------`)EOF");
    printf("\n[+] Your scan will now begin!\n\n");
}
