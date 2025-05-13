#ifndef PIPELOGGER_H_
#define PIPELOGGER_H_

#include <string>

namespace Logger {

	void LogOuput(const std::string& msg);

	void Cleanup();
}

#endif
