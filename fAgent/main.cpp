// Main file to initiate EDR Agent which will log messages to the console for us as it is running
// Via a named pipe server

#include <iostream>
#include <stdio.h>
#include <thread>
#include <string>
#include <Windows.h>

// HandleConnection defintions
void HandleConnection(HANDLE hPipe) {
	char buffer[1024];
	DWORD dwBytesRead = 0;

	while (true) {
		BOOL result = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwBytesRead, NULL);
		if (!result || dwBytesRead == 0) {
			break;
		}

		buffer[dwBytesRead] = '\0';
		std::cout << buffer << std::endl;
	}
	return;
}
// Init Named Pipe Server 
void InitPipeSvr() {
	printf("Waiting for client connection...\n");
	while (true) {
		HANDLE hPipe = CreateNamedPipeW(TEXT("\\\\.\\pipe\\Sk3lex0rPipe"), PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 1024, 1024, 0, NULL);
		if (hPipe == INVALID_HANDLE_VALUE) {
			printf("EDR Agent: Failed to create named pipe: 0x%x\n", GetLastError());
			return;
		}

		BOOL isConn = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError()) == ERROR_PIPE_CONNECTED;
		if (isConn) {
			printf("EDR Agent: Client Connection Recieved\n");
			std::thread ClientThread(HandleConnection, hPipe);

			// Detach Thread once connection is closed
			ClientThread.detach();
		}
		else {
			// Cleanup
			CloseHandle(hPipe);
		}

	}
}
int main() {

	printf("EDR Agent: Starting Named Pipe Server\n");

	// InitPipeSvr
	InitPipeSvr();
	return 0;
}