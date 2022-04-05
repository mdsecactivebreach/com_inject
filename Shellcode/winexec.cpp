
//
// WinExec("notepad", SW_SHOW) shellcode.
//
#include <windows.h>
#include <winternl.h>

typedef UINT
(WINAPI* WinExec_T)(LPCSTR lpCmdLine, UINT uCmdShow);

DWORD
ThreadProc(LPVOID lpParameter) {
    auto Ldr = (PPEB_LDR_DATA)NtCurrentTeb()->ProcessEnvironmentBlock->Ldr;
    auto Head = (PLIST_ENTRY)&Ldr->Reserved2[1];
    auto Next = Head->Flink;
    WinExec_T pWinExec = NULL;

    while (Next != Head && !pWinExec) {
        auto ent = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, Reserved1[0]);
        Next = Next->Flink;
        auto m = (PBYTE)ent->DllBase;
        auto nt = (PIMAGE_NT_HEADERS)(m + ((PIMAGE_DOS_HEADER)m)->e_lfanew);
        auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!rva) continue;
        auto exp = (PIMAGE_EXPORT_DIRECTORY)(m + rva);
        if (!exp->NumberOfNames) continue;
        auto dll = (PDWORD)(m + exp->Name);
        // find kernel32.dll
        if ((dll[0] | 0x20202020) != 'nrek') continue;
        if ((dll[1] | 0x20202020) != '23le') continue;
        if ((dll[2] | 0x20202020) != 'lld.') continue;

        auto adr = (PDWORD)(m + exp->AddressOfFunctions);
        auto sym = (PDWORD)(m + exp->AddressOfNames);
        auto ord = (PWORD)(m + exp->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            auto api = (PDWORD)(m + sym[i]);
            // find WinExec
            if (api[0] != 'EniW') continue;
            pWinExec = (WinExec_T)(m + adr[ord[i]]);
            DWORD cmd[2];
            cmd[0] = 'eton';
            cmd[1] = '\0dap';
            // execute notepad
            pWinExec((LPCSTR)cmd, SW_SHOW);
            break;
        }
    }
    return 0;
}

#include <cstdio>
#include <cstdlib>
int
main(void) {
    FILE* out;
    fopen_s(&out, "notepad.bin", "wb");
    fwrite((void*)ThreadProc, (PBYTE)main - (PBYTE)ThreadProc, 1, out);
    fclose(out);
}
