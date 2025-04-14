#ifndef XOR_H_
#define XOR_H_

#include <Windows.h>
PBYTE XorPayload(_In_ unsigned char payload[], _In_ SIZE_T payloadLength, _In_ BYTE key) {
	for (SIZE_T i{ 0 }; i < payloadLength; i++) {
		payload[i] = payload[i] ^ key;
	}
	return payload;
}





#endif


