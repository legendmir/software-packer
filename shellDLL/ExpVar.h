#pragma once
#include<windows.h>
typedef struct DllExpInfo
{
	DWORD dwOep;
	DWORD dwKey;
	char* pSecHeaderBuff;

	//DWORD dwSecNum;
	//DWORD dwDecryptSecBeginPoint[20];
	//DWORD dwDecryptSecSize[20];
}DllExpInfo;