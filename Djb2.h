#ifndef DJB2_H_
#define DJB2_H_

/*
Simple function to calculate hash of NTDLL for comparison
*/

#define INITIAL_HASH 9011
#define INITIAL_SEED 8

#include <Windows.h>
#include <iostream>

DWORD Djb2HashMaker(_In_ PWCHAR Value) {

	ULONG Hash = INITIAL_HASH;
	INT c;

	while (c = *Value++)
		Hash = ((Hash << INITIAL_SEED) + Hash) + c;

	return Hash;
}

#endif
