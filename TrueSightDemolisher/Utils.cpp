#include "Utils.h"
#include <iostream>


void RaiseError(const char* Message) {
	 auto le = GetLastError();
	 std::cerr << Message;
	 if (le) {
		 // shameless copy from stackoverflow

		 LPSTR messageBuffer = nullptr;

		 //Ask Win32 to give us the string version of that message ID.
		 //The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
		 size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			 NULL, le, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

		 //Copy the error message into a std::string.
		 std::string message(messageBuffer, size);

		 //Free the Win32's string's buffer.
		 LocalFree(messageBuffer);

		 std::cerr << ". Windows error code: " << le << ", (" << message << ")";
	 }
	 std::cerr << std::endl;
	 exit(-1);
}