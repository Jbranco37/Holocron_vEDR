#include "pch.h"
#include "PipeLogger.h"
#include <Windows.h>
#include <string>

// define namespace to better organize functions and variables

namespace Logger {

	// Define Info we want to print va the pipe
	HANDLE hPipe = INVALID_HANDLE_VALUE;
	std::string procName = "";
	DWORD dwPID = 0;

	void GetCurrProcInfo(std::string& procName, DWORD& dwPID) {
		// Retrieve PID of current process
		dwPID = GetCurrentProcessId();
		// Retireve file name
		char filePath[MAX_PATH];
		if (GetModuleFileNameA(NULL, filePath, MAX_PATH) > 0) {
			char* fileName = strrchr(filePath, '\\');
			if (fileName != NULL) {
				procName = std::string(fileName + 1);
			}
			else {
				procName = "Unknown";
			}
		}
	}

	bool OpenConnect() {
		if (hPipe == INVALID_HANDLE_VALUE) {
			hPipe = CreateFileA("\\\\.\\pipe\\Sk3lex0rPipe", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hPipe == INVALID_HANDLE_VALUE) {
				return false;
			}
		}

		return true;
	}

	void LogOuput(const std::string& msg) {
		if (dwPID == 0) {
			GetCurrProcInfo(procName, dwPID);
		}
		DWORD dwBytesWritten{ 0 };
		if (!OpenConnect()) {
			return;
		}
		std::string logOutput = msg;

		if (!WriteFile(hPipe, logOutput.c_str(), logOutput.length(), &dwBytesWritten, NULL)) {
			CloseHandle(hPipe);
			hPipe = INVALID_HANDLE_VALUE;
		}

	}

	void Cleanup() {

		if (hPipe != INVALID_HANDLE_VALUE){
			CloseHandle(hPipe);
		}
	}

};
