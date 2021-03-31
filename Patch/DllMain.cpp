/*

    by razor#3546
    steamid64: 76561198041755013

*/

#include <Windows.h>
#include "SigScan.hpp"

void InstallPatch()
{
    byte* HighPingKickAddress = (byte*)SigScan::FindAddress(
        GetModuleHandleA("FC_m64.dll"), 
        (const byte*)"\x40\x55\x53\x56\x57\x41\x57\x48\x8D\xAC\x24\x00\x00\x00\x00\x48\x81\xEC\x00\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x31\xE0\x48\x89\x85\x00\x00\x00\x00\x49\x89\xCF", 
        "xxxxxxxxxxx????xxx????xxx????xxxxxx????xxx", 
        ".edata"
    );

    if (HighPingKickAddress == NULL)
    {
        MessageBoxA(NULL, "SigScan failed", NULL, MB_OK);

        return;
    }

    DWORD OldProtect;
    VirtualProtect(HighPingKickAddress, 0x1000, PAGE_EXECUTE_READWRITE, &OldProtect);
    HighPingKickAddress[0] = 0x33; HighPingKickAddress[1] = 0xC0;   /*xor eax, eax*/
    HighPingKickAddress[2] = 0xC3;                                  /*retn*/
    VirtualProtect(HighPingKickAddress, 0x1000, OldProtect, &OldProtect);

    MessageBoxA(NULL, "Patch successful", "HighPingKickPatch", MB_OK);
}

BOOL WINAPI 
DllMain(void*, DWORD Reason, void*)
{
    if (Reason == DLL_PROCESS_ATTACH)
    {
        InstallPatch();
    }

    return TRUE;
}