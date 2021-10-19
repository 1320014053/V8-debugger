#include<stdio.h>
#include <windows.h>
#include <time.h>
#include <psapi.h>
#include "debugger.h"

DWORD64 CopiedByteCodeHandlerAddressJumpIfFalse = NULL;
DWORD64 ByteCodeHandlerAddressJumpIfFalse = NULL;
byte g_SaveByte[256] = { 0 };
HANDLE g_process;
HANDLE g_thread;
DWORD64 g_LastAddress;
int TotaltTriggered=0;

char* join(char* s1, char* s2) {
    char* result = malloc(strlen(s1) + strlen(s2) + 1);
    if (result == NULL) exit(1);
    strcpy(result, s1);
    strcat(result, s2);
}


int hexstringtobyte(char* in, unsigned char* out) {
    int len = (int)strlen(in);
    char* str = (char*)malloc(len);
    memset(str, 0, len);
    memcpy(str, in, len);
    for (int i = 0; i < len; i += 2) {
        //小写转大写
        if (str[i] >= 'a' && str[i] <= 'f') str[i] = str[i] & ~0x20;
        if (str[i + 1] >= 'a' && str[i] <= 'f') str[i + 1] = str[i + 1] & ~0x20;
        //处理第前4位
        if (str[i] >= 'A' && str[i] <= 'F')
            out[i / 2] = (str[i] - 'A' + 10) << 4;
        else
            out[i / 2] = (str[i] & ~0x30) << 4;
        //处理后4位, 并组合起来
        if (str[i + 1] >= 'A' && str[i + 1] <= 'F')
            out[i / 2] |= (str[i + 1] - 'A' + 10);
        else
            out[i / 2] |= (str[i + 1] & ~0x30);
    }
    free(str);
    return 0;
}

DWORD64 ScanAddress(HANDLE process, char* markCode) {
    int len = strlen(markCode) / 2;
    byte* markcodeonbyte = (byte*)malloc(strlen(markCode) / 2);
    memset(markcodeonbyte, 0, strlen(markCode) / 2);
    hexstringtobyte(markCode, markcodeonbyte);
    //printf("%d\r\n", markcodeonbyte[0]);
    SYSTEM_INFO lpSystemInfo;
    memset((void*)&lpSystemInfo, 0, sizeof(lpSystemInfo));
    GetNativeSystemInfo(&lpSystemInfo);
    MEMORY_BASIC_INFORMATION IpBuffer;
    memset((void*)&IpBuffer, 0, sizeof(IpBuffer));
    size_t size = VirtualQueryEx(process, lpSystemInfo.lpMinimumApplicationAddress, &IpBuffer, sizeof(IpBuffer));
    DWORD64 textaddr = (DWORD64)lpSystemInfo.lpMinimumApplicationAddress + IpBuffer.RegionSize;
    memset((void*)&IpBuffer, 0, sizeof(IpBuffer));
    size_t count;
    for (int i = 0; i < 800; i++) {
        size_t size = VirtualQueryEx(process, textaddr, &IpBuffer, sizeof(IpBuffer));
        //printf("Rdata session address:0x%p\r\n", IpBuffer.BaseAddress);
        //printf("Rdata session size:0x%p\r\n", IpBuffer.RegionSize);
        textaddr = (DWORD64)IpBuffer.BaseAddress + IpBuffer.RegionSize;
        if (IpBuffer.Protect == 0) {
            continue;
        }
        if (IpBuffer.AllocationBase == 0) {
            continue;
        }
        byte* buffer = (byte*)malloc(IpBuffer.RegionSize + 2);
        if (buffer == 0) {
            continue;
        }
        memset(buffer, 0, IpBuffer.RegionSize + 2);
        count = 0;
        BOOL ret = ReadProcessMemory(process, (LPCVOID)IpBuffer.BaseAddress, (LPVOID)buffer, IpBuffer.RegionSize, &count);
        if (count == 0) {
            continue;
        }
        int k = 0;
        for (int i = 0; i <= (int)count; i++) {
            if (markcodeonbyte[k] == buffer[i]) {
                k++;
                if (k == len) {
                    free(markcodeonbyte);
                    free(buffer);
                    return (DWORD64)IpBuffer.BaseAddress + (i - len + 1);
                }
                continue;
            }
            k = 0;
        }
        free(buffer);
        memset((void*)&IpBuffer, 0, sizeof(IpBuffer));
    }
    //byte* buffer = (byte*)malloc(IpBuffer.RegionSize + 2);
    //memset(buffer, 0, IpBuffer.RegionSize + 2);
    //size_t count;
    //BOOL ret = ReadProcessMemory(process, textaddr, (LPVOID)buffer, IpBuffer.RegionSize, &count);
    ////printf("%d\r\n", buffer[0]);
    ////printf("%d\r\n", count);
    //int k = 0;
    //for (int i = 0; i <= (int)count; i++) {
    //    if (markcodeonbyte[k] == buffer[i]) {
    //        k++;
    //        if (k == len) {
    //            free(markcodeonbyte);
    //            free(buffer);
    //            return (DWORD64)IpBuffer.BaseAddress + (i - len + 1);
    //        }
    //        continue;
    //    }
    //    k = 0;
    //}
    free(markcodeonbyte);
    return 0;
}


void OnProcessCreated(const CREATE_PROCESS_DEBUG_INFO* pInfo) {
    g_process = pInfo->hProcess;
    g_thread = pInfo->hThread;
    //printf("Debuggee was created.\r\n");
}



void OnThreadCreated(const CREATE_THREAD_DEBUG_INFO* pInfo) {

    //printf("A new thread was created.\r\n");
}



int OnException(const EXCEPTION_DEBUG_INFO* pInfo) {
    size_t count = 0;
    CONTEXT context;
    if (pInfo->ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT) {
        if (pInfo->ExceptionRecord.ExceptionCode != EXCEPTION_SINGLE_STEP) {
            return DBG_EXCEPTION_NOT_HANDLED;
        }
    }
    if (pInfo->ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
        byte tmp = { 0xcc };
        WriteProcessMemory(g_process, (LPVOID)g_LastAddress, &tmp, sizeof(g_SaveByte[JumpIfFalseHandler]), &count);
        count = 0;
    }

    printf("An exception was occured.\r\n");
    printf("ExceptionCode: %p\r\n", pInfo->ExceptionRecord.ExceptionCode);
    printf("ExceptionAddress: %p\r\n\r\n", pInfo->ExceptionRecord.ExceptionAddress);
    DWORD64 kk = (DWORD64)pInfo->ExceptionRecord.ExceptionAddress;
    kk = kk >> 36;

    if (kk == 0x7FF) {
        return DBG_EXCEPTION_NOT_HANDLED;
    }

    if (CopiedByteCodeHandlerAddressJumpIfFalse == NULL) {
        char* tmp = join("CC", "4889E56A1C4883EC38488B5500438D3C094C8B42F8415457504C897DE84C8965D04C894DE0488945F0488955D848897DC0498BF0498B9D08290000B8030000004C8BD8E8373AF6FF488B55E0488B7DD0440FB64417014C8945C8488B45F0413985B000000074574C8B45D84D8B58F84C8B75C04D8970D857415650498B9D10290000B803000000498BF3E8F039F6FF488B55D8488B52E04C8B5DE04D8D4B02410FB63C114C8B7DE8498B0CFF488B6D004C8BE2488B4424304883C448FFE14C8B5DD84D8B73F0458B76134D03F5418B5E07418D5C18FE41895E07498B5BF84C8B75C04D8973D857415650488BF3498B9D10290000B803000000E88139F6FF488B55D8488B52E0488B7DE04C8B45C84E8D0C07410FB63C114C8B7DE8498B0CFF488B6D004C8BE2488B4424304883C448FFE1");
        CopiedByteCodeHandlerAddressJumpIfFalse = ByteCodeHandlerAddressJumpIfFalse = ScanAddress(g_process, tmp);
        printf("CopiedByteCodeHandlerAddressJumpIfFalse Copied: 0x%p\r\n\r\n", CopiedByteCodeHandlerAddressJumpIfFalse);
        free(tmp);
    }
    if (pInfo->ExceptionRecord.ExceptionAddress == ByteCodeHandlerAddressJumpIfFalse) {
        WriteProcessMemory(g_process, (LPVOID)CopiedByteCodeHandlerAddressJumpIfFalse, &g_SaveByte[JumpIfFalseHandler], sizeof(g_SaveByte[JumpIfFalseHandler]), &count);
        count = 0;
        context.ContextFlags = CONTEXT_FULL;
        GetThreadContext(g_thread, &context);
        context.Rip = context.Rip - 1;
        context.EFlags |= 0x100;
        SetThreadContext(g_thread, &context);
        g_LastAddress = context.Rip;
        printf("JumpIfFalseHadler is triggered\r\n\r\n");
        TotaltTriggered++;
        printf("JumpIfFalseHadler triggered:%d\r\n\r\n", TotaltTriggered);
    }
    return 0;
}



void OnProcessExited(const EXIT_PROCESS_DEBUG_INFO* pInfo) {

    //printf("Debuggee was terminated.\r\n");
}



void OnThreadExited(const EXIT_THREAD_DEBUG_INFO* pInfo) {

    //printf("A thread was terminated.\r\n");
}



void OnOutputDebugString(const OUTPUT_DEBUG_STRING_INFO* pInfo) {

    //printf("Debuggee outputed debug string.\r\n");
}



void OnRipEvent(const RIP_INFO* pInfo) {

    //printf("A RIP_EVENT occured\r\n");
}



void OnDllLoaded(const LOAD_DLL_DEBUG_INFO* pInfo) {

    //printf("A dll was loaded.\r\n");
}



void OnDllUnloaded(const UNLOAD_DLL_DEBUG_INFO* pInfo) {

    //printf("A dll was unloaded.\r\n");
}


BOOL WriteInt3(HANDLE process, DWORD64 addr) {
    size_t count = 0;
    BOOL ret = ReadProcessMemory(process, (LPCVOID)addr, &g_SaveByte[JumpIfFalseHandler], sizeof(g_SaveByte[JumpIfFalseHandler]), &count);
    if (count == 0) {
        return FALSE;
    }
    count = 0;
    byte tmp = { 0xcc };
    ret = WriteProcessMemory(process, (LPVOID)addr, &tmp, sizeof((byte)0xcc), &count);
    if (count == 0) {
        return FALSE;
    }
    return TRUE;
}

int main() {
    int RetFromOnException;
    STARTUPINFO startupinfo;
    PROCESS_INFORMATION process_information;
    GetStartupInfo(&startupinfo);
    CreateProcessA("C:\\v836\\v8\\out.gn\\x64.release\\d8.exe", " js.js", NULL, NULL, FALSE, DEBUG_PROCESS, NULL, "C:\\v836\\v8\\out.gn\\x64.release\\", &startupinfo, &process_information);

    ByteCodeHandlerAddressJumpIfFalse = ScanAddress(process_information.hProcess, "554889E56A1C4883EC38488B5500438D3C094C8B42F8415457504C897DE84C8965D04C894DE0488945F0488955D848897DC0498BF0498B9D08290000B8030000004C8BD8E8373AF6FF488B55E0488B7DD0440FB64417014C8945C8488B45F0413985B000000074574C8B45D84D8B58F84C8B75C04D8970D857415650498B9D10290000B803000000498BF3E8F039F6FF488B55D8488B52E04C8B5DE04D8D4B02410FB63C114C8B7DE8498B0CFF488B6D004C8BE2488B4424304883C448FFE14C8B5DD84D8B73F0458B76134D03F5418B5E07418D5C18FE41895E07498B5BF84C8B75C04D8973D857415650488BF3498B9D10290000B803000000E88139F6FF488B55D8488B52E0488B7DE04C8B45C84E8D0C07410FB63C114C8B7DE8498B0CFF488B6D004C8BE2488B4424304883C448FFE1");
    printf("ByteCodeHandlerAddressJumpIfFalse before copied: 0x%p\r\n\r\n", ByteCodeHandlerAddressJumpIfFalse);
    if (WriteInt3(process_information.hProcess, ByteCodeHandlerAddressJumpIfFalse) == 0) {
        return FALSE;
    }

    BOOL waitEvent = TRUE;
    DEBUG_EVENT debugEvent;
    while (waitEvent == TRUE && WaitForDebugEvent(&debugEvent, INFINITE)) {
        switch (debugEvent.dwDebugEventCode) {

        case CREATE_PROCESS_DEBUG_EVENT:
            OnProcessCreated(&debugEvent.u.CreateProcessInfo);
            break;

        case CREATE_THREAD_DEBUG_EVENT:
            OnThreadCreated(&debugEvent.u.CreateThread);
            break;

        case EXCEPTION_DEBUG_EVENT:
            RetFromOnException = OnException(&debugEvent.u.Exception);
            if (RetFromOnException == DBG_EXCEPTION_NOT_HANDLED) {
                ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
                continue;
            }
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            OnProcessExited(&debugEvent.u.ExitProcess);
            waitEvent = FALSE;
            break;

        case EXIT_THREAD_DEBUG_EVENT:
            OnThreadExited(&debugEvent.u.ExitThread);
            break;

        case LOAD_DLL_DEBUG_EVENT:
            OnDllLoaded(&debugEvent.u.LoadDll);
            break;

        case UNLOAD_DLL_DEBUG_EVENT:
            OnDllUnloaded(&debugEvent.u.UnloadDll);
            break;

        case OUTPUT_DEBUG_STRING_EVENT:
            OnOutputDebugString(&debugEvent.u.DebugString);
            break;

        case RIP_EVENT:
            OnRipEvent(&debugEvent.u.RipInfo);
            break;

        default:
            printf("Unknown debug event");
            break;
        }

        if (waitEvent == TRUE) {
            ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
        }
        else {
            break;
        }
    }

    //DWORD64 addr = ScanAddress(process_information.hProcess, "554889E56A1C4883EC38488B5500438D3C094C8B42F8415457504C897DE84C8965D04C894DE0488945F0488955D848897DC0498BF0498B9D08290000B8030000004C8BD8E8373AF6FF488B55E0488B7DD0440FB64417014C8945C8488B45F0413985B000000074574C8B45D84D8B58F84C8B75C04D8970D857415650498B9D10290000B803000000498BF3E8F039F6FF488B55D8488B52E04C8B5DE04D8D4B02410FB63C114C8B7DE8498B0CFF488B6D004C8BE2488B4424304883C448FFE14C8B5DD84D8B73F0458B76134D03F5418B5E07418D5C18FE41895E07498B5BF84C8B75C04D8973D857415650488BF3498B9D10290000B803000000E88139F6FF488B55D8488B52E0488B7DE04C8B45C84E8D0C07410FB63C114C8B7DE8498B0CFF488B6D004C8BE2488B4424304883C448FFE1");
    //printf("%p\r\n", addr);
    system("pause");
}