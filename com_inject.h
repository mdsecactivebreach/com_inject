
//
// Process Injection via COM
//

#pragma once

#ifndef UNICODE
#define UNICODE
#endif

#include <winsdkver.h>
#define WINVER 0x0601
#define _WIN32_WINNT 0x0601
#include <sdkddkver.h>

#define _WIN32_DCOM

#include <windows.h>
#include <shlwapi.h>
#include <hstring.h>
#include <tlhelp32.h>
#include <ctxtcall.h>
#include <objidl.h>
#include <winternl.h>
#include <objbase.h>
#include <comsvcs.h>
#include <shlobj.h>
#include <dbghelp.h>
#include <wbemidl.h>
#include <shlguid.h>

#include <cstdio>
#include <string>
#include <vector>
#include <deque>
#include <iostream>
#include <fstream>
#include <sstream>
#include <locale>
#include <codecvt>
//#include <filesystem>
#include <iomanip>

#ifdef _WIN64
#define __TARGET_ARCH__ "64"
#else
#define __TARGET_ARCH__ "32"
#endif

typedef struct tagSOleTlsData {
    /* 0x0000 */ void* pvThreadBase;
    /* 0x0008 */ void* pSmAllocator;
    /* 0x0010 */ ULONG  dwApartmentID;
    /* 0x0014 */ ULONG  dwFlags;
    /* 0x0018 */ LONG   TlsMapIndex;
    /* 0x0020 */ void** ppTlsSlot;
    /* 0x0028 */ ULONG  cComInits;
    /* 0x002c */ ULONG  cOleInits;
    /* 0x0030 */ ULONG  cCalls;
    /* 0x0038 */ void* pServerCall;
    /* 0x0040 */ void* pCallObjectCache;
    /* 0x0048 */ void* pContextStack;
    /* 0x0050 */ void* pObjServer;
    /* 0x0058 */ ULONG  dwTIDCaller;
    /* 0x0060 */ void* pCurrentCtxForNefariousReaders;
    /* 0x0068 */ void* pCurrentContext;
} SOleTlsData;

typedef enum _PLM_TASKCOMPLETION_CATEGORY_FLAGS {
    PT_TC_NONE = 0x0,
    PT_TC_PBM = 0x1,
    PT_TC_FILEOPENPICKER = 0x2,
    PT_TC_SHARING = 0x4,
    PT_TC_PRINTING = 0x8,
    PT_TC_GENERIC = 0x10,
    PT_TC_CAMERA_DCA = 0x20,
    PT_TC_PRINTER_DCA = 0x40,
    PT_TC_PLAYTO = 0x80,
    PT_TC_FILESAVEPICKER = 0x100,
    PT_TC_CONTACTPICKER = 0x200,
    PT_TC_CACHEDFILEUPDATER_LOCAL = 0x400,
    PT_TC_CACHEDFILEUPDATER_REMOTE = 0x800,
    PT_TC_ERROR_REPORT = 0x2000,
    PT_TC_DATA_PACKAGE = 0x4000,
    PT_TC_CRASHDUMP = 0x10000,
    PT_TC_STREAMEDFILE = 0x20000,
    PT_TC_PBM_COMMUNICATION = 0x80000,
    PT_TC_HOSTEDAPPLICATION = 0x100000,
    PT_TC_MEDIA_CONTROLS_ACTIVE = 0x200000,
    PT_TC_EMPTYHOST = 0x400000,
    PT_TC_SCANNING = 0x800000,
    PT_TC_ACTIONS = 0x1000000,
    PT_TC_KERNEL_MODE = 0x20000000,
    PT_TC_REALTIMECOMM = 0x40000000,
    PT_TC_IGNORE_NAV_LEVEL_FOR_CS = 0x80000000
} PLM_TASKCOMPLETION_CATEGORY_FLAGS;

static const CLSID
CLSID_OSTaskCompletion = {
    0x07fc2b94,
    0x5285,
    0x417e,
    { 0x8a, 0xc3, 0xc2, 0xce, 0x52, 0x40, 0xb0, 0xfa } };

static const IID
IID_IOSTaskCompletion = {
    0xc7e40572,
    0xc36a,
    0x43ea,
    { 0x9a, 0x40, 0xf3, 0xb1, 0x68, 0xda, 0x55, 0x58 } };

static const IID
IID_ITaskCompletionCallback = {
    0xe3a475cf,
    0x34ea,
    0x4e9a,
    { 0x9f, 0x3e, 0x48, 0xce, 0x5c, 0x6e, 0x4e, 0x57 } };

MIDL_INTERFACE("E3A475CF-34EA-4E9A-9F3E-48CE5C6E4E57")
ITaskCompletionCallback : public IUnknown{
    STDMETHOD(Proc3)(int p0, int p1);
};

static const CLSID
CLSID_CoreShellComServerRegistrar = {
    0x54e14197,
    0x88b0,
    0x442f,
    { 0xb9, 0xa3, 0x86, 0x83, 0x70, 0x61, 0xe2, 0xfb } };

static const IID
IID_ICoreShellComServerRegistrar = {
    0x27eb33a5,
    0x77f9,
    0x4afe,
    { 0xae, 0x05, 0x6f, 0xdb, 0xbe, 0x72, 0x0e, 0xe7 } };


MIDL_INTERFACE("27EB33A5-77F9-4AFE-AE05-6FDBBE720EE7")
ICoreShellComServerRegistrar : public IUnknown{

    STDMETHOD(RegisterCOMServer)        (REFCLSID   rclsid,
                                          LPUNKNOWN  pUnk,
                                          PDWORD     ServerTag);

    STDMETHOD(UnregisterCOMServer)      (DWORD      ServerTag);

    STDMETHOD(DuplicateHandle)          (DWORD      dwSourceProcessId,
                                          HANDLE     SourceHandle,
                                          DWORD      dwTargetProcessId,
                                          LPHANDLE   lpTargetHandle,
                                          DWORD      dwDesiredAccess,
                                          BOOL       bInheritHandle,
                                          DWORD      dwOptions);

    STDMETHOD(OpenProcess)              (DWORD      dwDesiredAccess,
                                          BOOL       bInheritHandle,
                                          DWORD      SourceProcessId,
                                          DWORD      TargetProcessId,
                                          LPHANDLE   lpTargetHandle);

    STDMETHOD(GetAppIdFromProcessId)    (DWORD      dwProcessId,
                                          HSTRING* AppId);

    STDMETHOD(CoreQueryWindowService)   (HWND       hWindowHandle,
                                          GUID* GuidInfo,
                                          IUnknown** IUnknownInterface);

    STDMETHOD(CoreQueryWindowServiceEx) (HWND       hWindowHandle,
                                          HWND       hHandle,
                                          GUID* GuidInfo,
                                          IUnknown** IUnknownInterface);

    STDMETHOD(GetUserContextForProcess) (DWORD      dwProcessId,
                                          LUID* ContextId);

    STDMETHOD(BeginTaskCompletion)      (DWORD      dwProcessId,
                                          ITaskCompletionCallback* pTaskCompletionCallback,
                                          PLM_TASKCOMPLETION_CATEGORY_FLAGS Flags,
                                          PDWORD     TaskId);

    STDMETHOD(EndTaskCompletion)        (DWORD      TaskId);
};

enum IPIDFlags {
    IPIDF_CONNECTING = 0x1,
    IPIDF_DISCONNECTED = 0x2,
    IPIDF_SERVERENTRY = 0x4,
    IPIDF_NOPING = 0x8,
    IPIDF_COPY = 0x10,
    IPIDF_VACANT = 0x80,
    IPIDF_NONNDRSTUB = 0x100,
    IPIDF_NONNDRPROXY = 0x200,
    IPIDF_NOTIFYACT = 0x400,
    IPIDF_TRIED_ASYNC = 0x800,
    IPIDF_ASYNC_SERVER = 0x1000,
    IPIDF_DEACTIVATED = 0x2000,
    IPIDF_WEAKREFCACHE = 0x4000,
    IPIDF_STRONGREFCACHE = 0x8000,
    IPIDF_UNSECURECALLSALLOWED = 0x10000
};

typedef struct tagMInterfacePointer {
    ULONG ulCntData;
    BYTE abData[1];
} MInterfacePointer;

typedef MInterfacePointer* PMInterfacePointer;

typedef __int64 OXID;
typedef unsigned hyper OID;
typedef REFGUID REFIPID;

struct IPID {
    WORD offset;     // These are reversed because of little-endian
    WORD page;       // These are reversed because of little-endian

    WORD pid;
    WORD tid;

    BYTE seq[8];
};

typedef struct tagSTDOBJREF {
    ULONG flags;
    ULONG cPublicRefs;
    OXID  oxid;
    OID   oid;
    IPID  ipid;
} STDOBJREF;

typedef struct tagREMQIRESULT {
    HRESULT hResult;
    STDOBJREF std;
} REMQIRESULT;

typedef struct tagREMINTERFACEREF {
    IPID ipid;
    ULONG cPublicRefs;
    ULONG cPrivateRefs;
} REMINTERFACEREF;

typedef __int64 PTRMEM;

typedef struct tagXAptCallback {
    PTRMEM    pfnCallback;          // what to execute. e.g. LoadLibraryA, EtwpCreateEtwThread
    PTRMEM    pParam;               // parameter to callback.
    PTRMEM    pServerCtx;           // combase!g_pMTAEmptyCtx
    PTRMEM    pUnk;                 // Not required
    GUID      iid;                  // Not required
    int       iMethod;              // Not required
    GUID      guidProcessSecret;    // combase!CProcessSecret::s_guidOle32Secret
} XAptCallback;

static const IID IID_IRundown = {
    0x00000134,
    0x0000,
    0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46} };

//
// Used on most recent builds of Windows.
//
MIDL_INTERFACE("00000134-0000-0000-C000-000000000046")
IRundown : public IUnknown{
    STDMETHOD(RemQueryInterface)         (REFIPID             ripid,
                                           ULONG               cRefs,
                                           USHORT              cIids,
                                           IID * iids,
                                           REMQIRESULT * *ppQIResults);

    STDMETHOD(RemAddRef)                 (USHORT              cInterfaceRefs,
                                           REMINTERFACEREF     InterfaceRefs[],
                                           HRESULT* pResults);

    STDMETHOD(RemRelease)                (USHORT              cInterfaceRefs,
                                           REMINTERFACEREF     InterfaceRefs[]);

    STDMETHOD(RemQueryInterface2)        (REFIPID             ripid,
                                           USHORT              cIids,
                                           IID* piids,
                                           HRESULT* phr,
                                           MInterfacePointer** ppMIFs);

    STDMETHOD(AcknowledgeMarshalingSets) (USHORT              cMarshalingSets,
                                           ULONG_PTR* pMarshalingSets);

    STDMETHOD(RemChangeRef)              (ULONG               flags,
                                           USHORT              cInterfaceRefs,
                                           REMINTERFACEREF     InterfaceRefs[]);

    STDMETHOD(DoCallback)                (XAptCallback* pParam);

    STDMETHOD(DoNonreentrantCallback)    (XAptCallback* pParam);

    STDMETHOD(GetInterfaceNameFromIPID)  (IPID* ipid,
                                           HSTRING* Name);

    STDMETHOD(RundownOid)                (ULONG               cOid,
                                           OID                 aOid[],
                                           BYTE                aRundownStatus[]);
};

//
// Used on legacy systems (Vista, Windows 7, Windows 2008)
//
MIDL_INTERFACE("00000134-0000-0000-C000-000000000046")
IRundownLegacy : public IUnknown{
    STDMETHOD(RemQueryInterface)         (REFIPID             ripid,
                                           ULONG               cRefs,
                                           USHORT              cIids,
                                           IID * iids,
                                           REMQIRESULT * *ppQIResults);

    STDMETHOD(RemAddRef)                 (USHORT              cInterfaceRefs,
                                           REMINTERFACEREF     InterfaceRefs[],
                                           HRESULT* pResults);

    STDMETHOD(RemRelease)                (USHORT              cInterfaceRefs,
                                           REMINTERFACEREF     InterfaceRefs[]);

    STDMETHOD(RemQueryInterface2)        (REFIPID             ripid,
                                           USHORT              cIids,
                                           IID* piids,
                                           HRESULT* phr,
                                           MInterfacePointer** ppMIFs);

    STDMETHOD(RemChangeRef)              (ULONG               flags,
                                           USHORT              cInterfaceRefs,
                                           REMINTERFACEREF     InterfaceRefs[]);

    STDMETHOD(DoCallback)                (XAptCallback* pParam);

    STDMETHOD(RundownOid)                (ULONG               cOid,
                                           OID                 aOid[],
                                           BYTE                aRundownStatus[]);
};

static const IID
IID_IMarshalEnvoy = {
    0x000001C8,
    0x0000,
    0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46} };

MIDL_INTERFACE("000001C8-0000-0000-C000-000000000046")
IMarshalEnvoy : public IUnknown{
    // IMarshalEnvoy
    STDMETHOD(GetEnvoyUnmarshalClass)(DWORD dwDestContext, CLSID * pclsid);
    STDMETHOD(GetEnvoySizeMax)       (DWORD dwDestContext, DWORD* pcb);
    STDMETHOD(MarshalEnvoy)          (IStream* pstm, DWORD dwDestContext);
    STDMETHOD(UnmarshalEnvoy)        (IStream* pstm, REFIID riid, void** ppv);
};

struct tagPageEntry {
    tagPageEntry* pNext;
    unsigned int dwFlag;
};

struct CInternalPageAllocator {
    ULONG64            _cPages;
    tagPageEntry** _pPageListStart;
    tagPageEntry** _pPageListEnd;
    UINT               _dwFlags;
    tagPageEntry       _ListHead;
    UINT               _cEntries;
    ULONG64            _cbPerEntry;
    USHORT             _cEntriesPerPage;
    void* _pLock;
};

// CPageAllocator CIPIDTable::_palloc structure in combase.dll
struct CPageAllocator {
    CInternalPageAllocator _pgalloc;
    PVOID                  _hHeap;
    ULONG64                _cbPerEntry;
    INT                    _lNumEntries;
};

typedef struct tagIPIDEntry {
    struct tagIPIDEntry* pNextIPID;      // next IPIDEntry for same object
    DWORD                dwFlags;        // flags (see IPIDFLAGS)
    ULONG                cStrongRefs;    // strong reference count
    ULONG                cWeakRefs;      // weak reference count
    ULONG                cPrivateRefs;   // private reference count
    void* pv;             // real interface pointer
    IUnknown* pStub;          // proxy or stub pointer
    void* pOXIDEntry;     // ptr to OXIDEntry in OXID Table
    IPID                 ipid;           // interface pointer identifier
    IID                  iid;            // interface iid
    void* pChnl;          // channel pointer
    void* pIRCEntry;      // reference cache line
    HSTRING* pInterfaceName;
    struct tagIPIDEntry* pOIDFLink;      // In use OID list
    struct tagIPIDEntry* pOIDBLink;
} IPIDEntry;

struct tagCTXVERSION {
    SHORT ThisVersion;
    SHORT MinVersion;
};

struct tagCTXCOMMONHDR {
    GUID  ContextId;
    DWORD Flags;
    DWORD Reserved;
    DWORD dwNumExtents;
    DWORD cbExtents;
    DWORD MshlFlags;
};

struct tagBYREFHDR {
    DWORD Reserved;
    DWORD ProcessId;
    GUID  guidProcessSecret;
    PVOID pServerCtx;          // CObjectContext
};

struct tagBYVALHDR {
    ULONG         Count;
    BOOL          Frozen;
} CTXBYVALHDR;

struct tagCONTEXTHEADER {
    tagCTXVERSION Version;
    tagCTXCOMMONHDR CmnHdr;

    union {
        tagBYVALHDR ByValHdr;
        tagBYREFHDR ByRefHdr;
    };
};

typedef struct tagSTRINGBINDING
{
    unsigned short wTowerId;
    unsigned short aNetworkAddr;
}   STRINGBINDING;

#define COM_C_AUTHZ_NONE    ( 0xffff )

typedef struct tagSECURITYBINDING
{
    unsigned short wAuthnSvc;
    unsigned short wAuthzSvc;
    unsigned short aPrincName;
}   SECURITYBINDING;

typedef struct tagDUALSTRINGARRAY
{
    unsigned short wNumEntries;
    unsigned short wSecurityOffset;
    /* [size_is] */ unsigned short aStringArray[1];
}   DUALSTRINGARRAY;

#define OBJREF_SIGNATURE    ( 0x574f454d )

#define OBJREF_STANDARD ( 0x1 )
#define OBJREF_HANDLER  ( 0x2 )
#define OBJREF_CUSTOM   ( 0x4 )
#define OBJREF_EXTENDED ( 0x8 )

#define SORF_OXRES1 ( 0x1 )
#define SORF_OXRES2 ( 0x20 )
#define SORF_OXRES3 ( 0x40 )
#define SORF_OXRES4 ( 0x80 )
#define SORF_OXRES5 ( 0x100 )
#define SORF_OXRES6 ( 0x200 )
#define SORF_OXRES7 ( 0x400 )
#define SORF_OXRES8 ( 0x800 )
#define SORF_NULL   ( 0 )
#define SORF_NOPING ( 0x1000 )

typedef struct tagDATAELEMENT
{
    GUID dataID;
    unsigned long cbSize;
    unsigned long cbRounded;
    /* [size_is] */ BYTE Data[1];
}   DATAELEMENT;

typedef struct tagOBJREFDATA
{
    unsigned long nElms;
    /* [unique][size_is][size_is] */ DATAELEMENT** ppElmArray;
}   OBJREFDATA;

typedef struct tagOBJREF
{
    unsigned long signature;
    unsigned long flags;
    GUID iid;
    /* [switch_type][switch_is] */ union
    {
        /* [case()] */ struct
        {
            STDOBJREF std;
            DUALSTRINGARRAY saResAddr;
        }   u_standard;
        /* [case()] */ struct
        {
            STDOBJREF std;
            CLSID clsid;
            DUALSTRINGARRAY saResAddr;
        }   u_handler;
        /* [case()] */ struct
        {
            CLSID clsid;
            unsigned long cbExtension;
            unsigned long size;
            /* [ref][size_is] */ byte* pData;
        }   u_custom;
        /* [case()] */ struct
        {
            STDOBJREF std;
            /* [unique] */ OBJREFDATA* pORData;
            DUALSTRINGARRAY saResAddr;
        }   u_extended;
    }   u_objref;
}   OBJREF;

//
// Holds information about the location of data required to invoke IRundown::DoCallback()
//
typedef struct _COM_CONTEXT {
    DWORD pid;                     // Process ID
    std::wstring name;             // Process name 

    std::wstring path;             // Full path of DLL or shellcode.
    bool inject_pic;               // Inject shellcode.
    bool inject_dll;               // Inject DLL into notepad.
    bool list_ipid, verbose;       // List IRundown instances or all COM.
    bool use_objref;               // If true, use CoGetObject() to bind with IRundown instance.

    PBYTE base;                    // GetModuleHandle("combase"); or GetModuleHandle("ole32");
    DWORD data;                    // VirtualAddress of .data segment
    DWORD size;                    // VirtualSize
    DWORD secret;                  // CProcessSecret::s_guidOle32Secret
    DWORD server_ctx;              // g_pMTAEmptyCtx
    DWORD ipid_tbl;                // CIPIDTable::_palloc
    DWORD oxid;                    // offsetof(tagOXIDEntry, OXID)
} COM_CONTEXT, * PCOM_CONTEXT;

//
// Holds information about an IRundown interface in remote COM process.
//
typedef struct _IPID_ENTRY {
    IID   iid;
    IPID  ipid;                // IPID to bind to
    OXID  oxid;                // Object Exporter ID
    OID   oid;
} IPID_ENTRY, * PIPID_ENTRY;

//
// Holds information about an instance of IRundown in remote COM process and
// information required to invoke the DoCallback method.
//
typedef struct _RUNDOWN_CONTEXT {
    PVOID pfnCallback;         // what to execute
    PVOID pParam;              // parameter to callback function

    PVOID pServerCtx;          // required for DoCallback validation
    GUID  guidProcessSecret;   // required for DoCallback validation

    IPID  ipid;                // IPID to bind to
    OXID  oxid;                // Object Exporter ID
    OID   oid;                 // Object Identifier
} RUNDOWN_CONTEXT, * PRUNDOWN_CONTEXT;

//
// Microsoft removed this prototype from oleacc.h, but the function still exists and works fine.
//
typedef HANDLE(WINAPI* GetProcessHandleFromHwnd_T)(
    _In_ HWND hwnd
    );

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
RtlAdjustPrivilege(
    _In_ ULONG Privilege,
    _In_ BOOLEAN Enable,
    _In_ BOOLEAN Client,
    _Out_ PBOOLEAN WasEnabled
);
