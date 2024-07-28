#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>

#pragma comment (lib, "wintrust.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "crypt32.lib")

#define MESSAGE_SIZE 2048


int main() {
    LPCWSTR pipeName = L"\\\\.\\pipe\\dumbedr-analyzer";
    DWORD bytesRead = 0;
    wchar_t target_binary_file[MESSAGE_SIZE] = { 0 };

    printf("Launching analyzer named pipe server\n");

    // Creates a named pipe
    HANDLE hServerPipe = CreateNamedPipe(
        pipeName,                 // Pipe name to create
        PIPE_ACCESS_DUPLEX,       // Whether the pipe is supposed to receive or send data (can be both)
        PIPE_TYPE_MESSAGE,        // Pipe mode (whether or not the pipe is waiting for data)
        PIPE_UNLIMITED_INSTANCES, // Maximum number of instances from 1 to PIPE_UNLIMITED_INSTANCES
        MESSAGE_SIZE,             // Number of bytes for output buffer
        MESSAGE_SIZE,             // Number of bytes for input buffer
        0,                        // Pipe timeout 
        NULL                      // Security attributes (anonymous connection or may be needs credentials. )
    );

    while (TRUE) {

        // ConnectNamedPipe enables a named pipe server to start listening for incoming connections
        BOOL isPipeConnected = ConnectNamedPipe(
            hServerPipe, // Handle to the named pipe
            NULL         // Whether or not the pipe supports overlapped operations
        );

        wchar_t message[MESSAGE_SIZE] = { 0 };
        if (isPipeConnected) {
            // Read from the named pipe
            ReadFile(
                hServerPipe,         // Handle to the named pipe
                &message, // Target buffer where to stock the output
                MESSAGE_SIZE,        // Size of the buffer
                &bytesRead,          // Number of bytes read from ReadFile
                NULL                 // Whether or not the pipe supports overlapped operations
            );

            printf("~> %ws\n", message);
            int res = 0;
        }
        
    }

    printf("Exit\n\n");

    // Disconnect
    DisconnectNamedPipe(
        hServerPipe // Handle to the named pipe
    );

    return 0;
}