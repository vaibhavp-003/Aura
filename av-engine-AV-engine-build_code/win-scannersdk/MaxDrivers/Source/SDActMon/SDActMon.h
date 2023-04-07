#pragma once
#include <fltKernel.h>
#include <wdm.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>

/*******************USB Constants****************************/
UNICODE_STRING USB_READ_VALUE = RTL_CONSTANT_STRING(L"USB-READ");
UNICODE_STRING USB_WRITE_VALUE = RTL_CONSTANT_STRING(L"USB-WRITE");
UNICODE_STRING USB_EXECUTE_VALUE = RTL_CONSTANT_STRING(L"USB-EXECUTE");
UNICODE_STRING USB_ACTIVITY_MON_VALUE = RTL_CONSTANT_STRING(L"USB-ACTIVITY");
UNICODE_STRING	TMP_FILE = RTL_CONSTANT_STRING(L"TMP");

const static UNICODE_STRING SYSTEM_PROCESS_NAME = RTL_CONSTANT_STRING(L"System");

ULONG	g_bMonitorUSB = 0;

ULONG	g_bTotalBlock = 0;
ULONG	g_bExecuteBlock = 0;
ULONG	g_bReadBlock = 0;
ULONG	g_bWriteBlock = 0;
ULONG	g_bActivityLog = 0;
ULONG	g_bActivityDLP = 0;

BOOLEAN GetUsbSettingsData(PUNICODE_STRING pusRegistryPath, const PUNICODE_STRING pusValueName);
int		IsRemovableMedia(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
int		IsUSBExecuteCall(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
int		IsUSBReadCall(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
int		IsUSBWriteCall(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

/***********************************************************/


//PFLT_FILTER FilterHandle = NULL;
#define MAXSYSMON_POOL_POOL_TAG		'pMX'
const static UNICODE_STRING BACKSLASH = RTL_CONSTANT_STRING(L"\\");
const PWSTR SDActMonPortName = L"\\SDActMonPort";
#define SDACTMON_READ_BUFFER_SIZE			512

UNICODE_STRING	EXE_FILE = RTL_CONSTANT_STRING(L"EXE");

//Required Structure
typedef NTSTATUS(*QUERY_INFO_PROCESS)(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);
QUERY_INFO_PROCESS ZwQueryInformationProcess;

typedef struct _SDACTMON_DATA
{
	PDRIVER_OBJECT	DriverObject;
	PFLT_FILTER		Filter;
	PFLT_PORT		ServerPort;
	PEPROCESS		UserProcess;
	PFLT_PORT		ClientPort;
	ULONG			ControlPid;
	ULONG			PendingRequests;
	NPAGED_LOOKASIDE_LIST QueueContextLookaside;
} SDACTMON_DATA, * PSDACTMON_DATA;

typedef struct _SDACTMON_STREAM_HANDLE_CONTEXT
{
	BOOLEAN OurFile;
	BOOLEAN RescanRequired;
	BOOLEAN BlockWriteAccess;
	DWORD	Type_Of_Call;
	UNICODE_STRING usProcessName;
	WCHAR	szProcessName[256];
	UNICODE_STRING usFullFileName;
	WCHAR	szFullFileName[256];
} SDACTMON_STREAM_HANDLE_CONTEXT, * PSDACTMON_STREAM_HANDLE_CONTEXT;

typedef struct _INSTANCE_CONTEXT
{
	//
	//  Instance for this context.
	//
	PFLT_INSTANCE Instance;

	//
	//  Cancel safe queue members
	//
	FLT_CALLBACK_DATA_QUEUE Cbdq;
	LIST_ENTRY QueueHead;
	FAST_MUTEX Lock;

	//
	//  Flag to control the life/death of the work item thread
	//
	volatile LONG WorkerThreadFlag;

	//
	//  Notify the worker thread that the instance is being torndown
	//
	KEVENT TeardownEvent;
}INSTANCE_CONTEXT, * PINSTANCE_CONTEXT;

typedef struct _QUEUE_CONTEXT
{
	FLT_CALLBACK_DATA_QUEUE_IO_CONTEXT CbdqIoContext;
	SDACTMON_STREAM_HANDLE_CONTEXT ScanContext;
}QUEUE_CONTEXT, * PQUEUE_CONTEXT;


typedef struct _SDACTMON_NOTIFICATION
{
	HANDLE ProcessID;
	ULONG Reserved_1;			// for quad-word alignement of the Contents structure
	ULONG TypeOfCall;
	ULONG Reserved_2;			// for quad-word alignement of the Contents structure
	ULONG IsIgnored;
	ULONG Reserved_3;			// for quad-word alignement of the Contents structure

	ULONG TypeOfReplication;
	UCHAR ProcessName[SDACTMON_READ_BUFFER_SIZE];
	UCHAR Accessed_1[SDACTMON_READ_BUFFER_SIZE];
	UCHAR Accessed_2[SDACTMON_READ_BUFFER_SIZE];
} SDACTMON_NOTIFICATION, * PSDACTMON_NOTIFICATION;

typedef struct _SDACTMON_REPLY
{
	BOOLEAN SafeToOpen;
} SDACTMON_REPLY, * PSDACTMON_REPLY;

//Functions
NTSTATUS	DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTSTATUS	ActMonUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
BOOLEAN		GetImageNameByID(HANDLE ProcessId, PUNICODE_STRING pusImageFileName);
NTSTATUS	GetProcessImageName(HANDLE ProcessHandle, PUNICODE_STRING ProcessImageName);
USHORT		GetMaxLen(PUNICODE_STRING pStr);
BOOLEAN		GetProcessNameEx(PUNICODE_STRING ProcessImageName);

NTSTATUS DriverDeviceControlHandler(IN PDEVICE_OBJECT device, IN PIRP Irp);

BOOLEAN IsOurPathFile(PUNICODE_STRING FileBeingAccessed);
BOOLEAN IsOurProcessFile(PUNICODE_STRING ProcessPath);
BOOLEAN MatchUnicodeString(UNICODE_STRING const* pusLeftString, UNICODE_STRING const* pusRightString);
BOOLEAN MatchWCHARString(int iwLen, PWCHAR w, int isLen, PWCHAR s);
BOOLEAN IsOurProcessByID(HANDLE dwProcessID);

NTSTATUS GetMaxFileInfo(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject, _Out_ PBOOLEAN IsDir, _Out_ PLONGLONG FileSize);

//Callback Functions
//IRP_MJ_CREATE
FLT_PREOP_CALLBACK_STATUS ActMonPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_POSTOP_CALLBACK_STATUS ActMonPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext, FLT_POST_OPERATION_FLAGS Flags);

//IRP_MJ_CLEANUP
FLT_PREOP_CALLBACK_STATUS ActMonPreCleanup(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects,__deref_out_opt PVOID* CompletionContext);
FLT_POSTOP_CALLBACK_STATUS ActMonPostCleanup(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID* CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags);

//IRP_MJ_WRITE
FLT_PREOP_CALLBACK_STATUS ActMonPreWrite(_Inout_ PFLT_CALLBACK_DATA Data,_In_ PCFLT_RELATED_OBJECTS FltObjects,_Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

//IRP_MJ_SET_INFORMATION
FLT_PREOP_CALLBACK_STATUS ActMonPreSetInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

//Communication Channel
VOID ContextCleanup(__in PFLT_CONTEXT Context, __in FLT_CONTEXT_TYPE ContextType);
NTSTATUS ActMonPortConnect(__in PFLT_PORT ClientPort, __in_opt PVOID ServerPortCookie,__in_bcount_opt(SizeOfContext) PVOID ConnectionContext, __in ULONG SizeOfContext,__deref_out_opt PVOID* ConnectionCookie);
VOID	 ActMonPortDisconnect(__in_opt PVOID ConnectionCookie);

BOOLEAN SendEntryToUI(ULONG ulTypeOfCall, PUNICODE_STRING pusProcessName, PUNICODE_STRING pAccessed_1, PUNICODE_STRING pAccessed_2);

NTSTATUS DriverCreateCloseHandler(IN PDEVICE_OBJECT device, IN PIRP Irp);
NTSTATUS DriverCleanupHandler(IN PDEVICE_OBJECT device, IN PIRP Irp);
void DriverUnloadHandler(IN PDRIVER_OBJECT driver);

BOOLEAN IsFileWriteCall(__inout PFLT_CALLBACK_DATA Data);

VOID __drv_maxIRQL(APC_LEVEL) __drv_setsIRQL(APC_LEVEL) CsqAcquire(__in PFLT_CALLBACK_DATA_QUEUE DataQueue, __out PKIRQL Irql);
VOID __drv_maxIRQL(APC_LEVEL) __drv_minIRQL(APC_LEVEL) __drv_setsIRQL(PASSIVE_LEVEL) CsqRelease(__in PFLT_CALLBACK_DATA_QUEUE DataQueue, __in KIRQL Irql);
NTSTATUS CsqInsertIo(__in PFLT_CALLBACK_DATA_QUEUE DataQueue, __in PFLT_CALLBACK_DATA Data, __in_opt PVOID Context);
VOID CsqRemoveIo(__in PFLT_CALLBACK_DATA_QUEUE DataQueue, __in PFLT_CALLBACK_DATA Data);
PFLT_CALLBACK_DATA CsqPeekNextIo(__in PFLT_CALLBACK_DATA_QUEUE DataQueue, __in_opt PFLT_CALLBACK_DATA Data, __in_opt PVOID PeekContext);
VOID CsqCompleteCanceledIo(__in PFLT_CALLBACK_DATA_QUEUE DataQueue, __inout PFLT_CALLBACK_DATA Data);
VOID WorkItemRoutine(__in PFLT_GENERIC_WORKITEM WorkItem, __in PFLT_FILTER Filter, __in PVOID Context);
VOID EmptyQueueAndComplete(__in PINSTANCE_CONTEXT InstanceContext);

NTSTATUS SDActMonInstanceSetup(__in PCFLT_RELATED_OBJECTS FltObjects, __in FLT_INSTANCE_SETUP_FLAGS Flags,
	__in DEVICE_TYPE VolumeDeviceType, __in FLT_FILESYSTEM_TYPE VolumeFilesystemType);
NTSTATUS SDActMonQueryTeardown(__in PCFLT_RELATED_OBJECTS FltObjects, __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

VOID SDActMonInstanceTeardownStart(__in PCFLT_RELATED_OBJECTS FltObjects, __in FLT_INSTANCE_TEARDOWN_FLAGS Flags);
VOID SDActMonInstanceTeardownComplete(__in PCFLT_RELATED_OBJECTS FltObjects, __in FLT_INSTANCE_TEARDOWN_FLAGS Flags);

NTSTATUS AddInQue(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, ULONG ulTypeOfCall, PUNICODE_STRING pusProcessName, PUNICODE_STRING pusFullFileName);
//Constatnts

BOOLEAN IsAllowedStateCreate(__in PCFLT_RELATED_OBJECTS FltObjects, __in FLT_POST_OPERATION_FLAGS Flags);
BOOLEAN IsPostCreateSkip(__in PFLT_CALLBACK_DATA Data,__in PCFLT_RELATED_OBJECTS FltObjects,__in FLT_POST_OPERATION_FLAGS Flags);
int		CheckIsWinDll(PUNICODE_STRING pEntryPath);
int		IsNeedToCheckEncryption(PUNICODE_STRING pEntryPath, PUNICODE_STRING pFileExt);


const ULONG CALL_TYPE_UNKNOWN = 0;
const ULONG CALL_TYPE_F_EXECUTE = 1;
const ULONG CALL_TYPE_F_CREATE = 2;
const ULONG CALL_TYPE_F_OPEN = 3;
const ULONG CALL_TYPE_F_DELETE = 4;
const ULONG CALL_TYPE_F_RENAME = 5;
const ULONG CALL_TYPE_R_CREATE = 6;
const ULONG CALL_TYPE_R_OPEN = 7;
const ULONG CALL_TYPE_R_DELETE = 8;
const ULONG CALL_TYPE_R_RENAME = 9;
const ULONG CALL_TYPE_R_SETVAL = 10;
const ULONG CALL_TYPE_R_DELETEVAL = 11;
const ULONG CALL_TYPE_D_CREATE = 12;
const ULONG CALL_TYPE_F_NEW_FILE = 13;
const ULONG CALL_TYPE_F_NEW_SYS_FILE = 14;
const ULONG CALL_TYPE_F_REN_SYS_FILE = 15;
const ULONG CALL_TYPE_F_DEL_SYS_FILE = 16;
const ULONG CALL_TYPE_F_MOD_SYS_FILE = 17;
const ULONG CALL_TYPE_F_KIDO_FILE = 18;
const ULONG CALL_TYPE_F_REPLICATING = 19;
const ULONG CALL_TYPE_F_R_BLOCK = 20;
const ULONG CALL_TYPE_C_CREATE = 21;
const ULONG CALL_TYPE_U_CREATE = 22;
const ULONG CALL_TYPE_U_WRITE = 23;
const ULONG CALL_TYPE_U_EXECUTE = 24;
const ULONG CALL_TYPE_N_CREATE = 25;
const ULONG CALL_TYPE_FIM_DELETE = 26;
const ULONG CALL_TYPE_FIM_RENAME = 27;
const ULONG CALL_TYPE_FIM_MODIFY = 28;
const ULONG CALL_TYPE_FIM_CREATE = 29;

const static int IOCTL_PAUSE_PROTECTION = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8001, METHOD_NEITHER, FILE_ANY_ACCESS);
const static int IOCTL_RESUME_PROTECTION = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8005, METHOD_IN_DIRECT, FILE_ANY_ACCESS);
const static int IOCTL_USB_TOTAL_BLOCK = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8009, METHOD_BUFFERED, FILE_ANY_ACCESS);
const static int IOCTL_USB_WRITE_BLOCK = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8010, METHOD_BUFFERED, FILE_ANY_ACCESS);
const static int IOCTL_USB_EXECUTE_BLOCK = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8011, METHOD_BUFFERED, FILE_ANY_ACCESS);
const static int IOCTL_USB_READ_BLOCK = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8012, METHOD_BUFFERED, FILE_ANY_ACCESS);
const static int IOCTL_USB_ACTIVITY_LOG = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8015, METHOD_BUFFERED, FILE_ANY_ACCESS);
const static int IOCTL_REGISTER_PROCESSID = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8006, METHOD_BUFFERED, FILE_ANY_ACCESS);

enum Max_Protected_Processes
{
	MAX_PROC_MAXSDUI,
	MAX_PROC_MAXSDTRAY,
	MAX_PROC_MAXUSB,
	MAX_PROC_MAXWATCHDOG,
	MAX_PROC_MAXSCANNER_OPTION,
	MAX_PROC_MAXSCANNER_USB,
	MAX_PROC_MAXSCANNER_MAIN,
	MAX_PROC_MAXSCANNER_HE,
	MAX_PROC_KEYLOGGERSCANNER,
	MAX_PROC_MAXCMDSCANNER,
	MAX_PROC_MAXDSRV,
	MAX_PROC_MAXPROTECTOR,
	MAX_PROC_MAXMERGER,
	MAX_PROC_MAXAVSETUP,
	MAX_PROC_SETUP,
	MAX_PROC_IEXPLORER,
	MAX_PROC_LIVEUPDATE,
	MAX_PROC_NOTIFICATION,
	MAX_PROC_MIGRATESD,
	MAX_PROC_MAXACTMON,
	MAX_PROC_MAXUSBPROC,
	MAX_PROC_MAXPROCSCN,
	MAX_PROC_MAXREGISTRYBACKUP,
	MAX_PROC_MAXROOTKITSCANNERUI,
	MAX_PROC_MAXUNINSTALLER,
	MAX_PROC_SENDREPORT,
	MAX_PROC_SUBMITSAMPLES,
	MAX_PROC_SDFRAUDTOOLFIX,
	MAX_PROC_MAXROOTKITSCANNER,
	MAX_PROC_MAXFSMON,
	MAX_PROC_MAXWSMON,
	MAX_PROC_MAXWSRMON,

	//Tools
	MAX_PROC_BACKUPRESTOREUTILITY,
	MAX_PROC_CMDREGISTRATION,
	MAX_PROC_MAXCLEANSYSVOLUME,
	MAX_PROC_MAXGENPROCHOST,
	MAX_PROC_MAXKIDOFIX,
	MAX_PROC_MAXREGISTRYFIX,
	MAX_PROC_MAXSALCLN,
	MAX_PROC_MAXSERVICESLIST,
	MAX_PROC_MAXTRJSCN,
	MAX_PROC_MAXUNHIDE,
	MAX_PROC_MAXUPDATEFIX,
	MAX_PROC_SETDACL,
	MAX_PROC_MAXSECUREREPORTS,

	//Firewall
	MAX_PROC_DRIVER_MGR,
	MAX_PROC_INTERSECINTERFACEXP,
	MAX_PROC_INTERSECSRVXP,
	MAX_PROC_MAILPROXY,
	MAX_PROC_FIREWALLSERVICE,

	//MTS
	MAX_PROC_MTS_UI,
	MAX_PROC_MTS_SCH,
	MAX_PROC_MTS_GADGET,

	//Outlook
	MAX_PROC_OUTLOOK,					// Do not add this in Process protection

	MAX_PROC_MAXPWDMGR,

	MAX_PROC_CLOUAVUI,
	MAX_PROC_MAXOPTCL,
	MAX_PROC_MAXWMGRSRV,
	MAX_PROC_MAXSECURECMD,

	MAX_PROC_LAPTOPTRACKER,
	MAX_PROC_MAXFIM,
	MAX_PROC_MAXRESERVE3,
	MAX_PROC_MAXRESERVE4,

	MAX_PROC_MAX_PROC_LAST_ENTRY		// Always add new application above this entry
};

DWORD dwProcessIDList[MAX_PROC_MAX_PROC_LAST_ENTRY] = { 0 };

/*
typedef struct _SDACTMON_STREAM_HANDLE_CONTEXT
{
	BOOLEAN OurFile;
	BOOLEAN RescanRequired;
	BOOLEAN BlockWriteAccess;
	DWORD	Type_Of_Call;
	UNICODE_STRING usProcessName;
	WCHAR	szProcessName[256];
	UNICODE_STRING usFullFileName;
	WCHAR	szFullFileName[256];
} SDACTMON_STREAM_HANDLE_CONTEXT, * PSDACTMON_STREAM_HANDLE_CONTEXT;
*/
//
//  Queue context data structure
//
/*
typedef struct _QUEUE_CONTEXT
{
	FLT_CALLBACK_DATA_QUEUE_IO_CONTEXT CbdqIoContext;
	SDACTMON_STREAM_HANDLE_CONTEXT ScanContext;
}QUEUE_CONTEXT, * PQUEUE_CONTEXT;
*/
//
//  Instance context data structure
//
/*
typedef struct _INSTANCE_CONTEXT
{
	//
	//  Instance for this context.
	//
	PFLT_INSTANCE Instance;

	//
	//  Cancel safe queue members
	//
	FLT_CALLBACK_DATA_QUEUE Cbdq;
	LIST_ENTRY QueueHead;
	FAST_MUTEX Lock;

	//
	//  Flag to control the life/death of the work item thread
	//
	volatile LONG WorkerThreadFlag;

	//
	//  Notify the worker thread that the instance is being torndown
	//
	KEVENT TeardownEvent;
}INSTANCE_CONTEXT, * PINSTANCE_CONTEXT;

typedef struct _SDACTMON_DATA
{
	PDRIVER_OBJECT	DriverObject;
	PFLT_FILTER		Filter;
	PFLT_PORT		ServerPort;
	PEPROCESS		UserProcess;
	PFLT_PORT		ClientPort;
	ULONG			ControlPid;
	ULONG			PendingRequests;
	NPAGED_LOOKASIDE_LIST QueueContextLookaside;
} SDACTMON_DATA, * PSDACTMON_DATA;
*/
/*
typedef enum _REQUEST_TYPE
{
	REQUEST_TYPE_PORT,
	REQUEST_TYPE_IPADDRESS,
	REQUEST_TYPE_NETWORK
}REQUEST_TYPE;

typedef struct _REQUEST_PARAMS
{
	REQUEST_TYPE rType;
}REQUEST_PARAMS, * PREQUEST_PARAMS;




extern SDACTMON_DATA SDActMonData;


#pragma warning(push)
#pragma warning(disable:4200) // disable warnings for structures with zero length arrays.

typedef struct _SDACTMON_CREATE_PARAMS
{
	WCHAR String[0];
} SDACTMON_CREATE_PARAMS, * PSDACTMON_CREATE_PARAMS;

typedef struct _DRVINFO {
	CHAR	szDrvName[4];
	CHAR	szVolName[25];
}DRVINFO, * PDRVINFO;

typedef struct _COPYINFO
{
	WCHAR	wSrcFile[260];
	WCHAR	wDstFile[260];
}COPYINFO, * PCOPYINFO;

DRVINFO DrvInfo[26];


typedef struct _MONITOR_DATA_FLOW
{
	LIST_ENTRY		ListEntry;
	int				NumberofCalls;
	ULONG			dwParentProcessId;
	ULONG			dwProcessId;
	LONGLONG		FileSize;
	UNICODE_STRING	usFileLocation1;
	WCHAR			wsFileLocation1[256];
	UNICODE_STRING	usFileLocation2;
	WCHAR			wsFileLocation2[256];
	UNICODE_STRING	usFileLocation3;
	WCHAR			wsFileLocation3[256];
	UNICODE_STRING	usParentName;
	WCHAR			wsParentName[256];
	USHORT			NumberSuspectedRegCalls;
	BOOLEAN			AreFilesToBeDeleted;
}MONITOR_DATA_FLOW, * PMONITOR_DATA_FLOW;


typedef struct _MONITOR_IEXPLORE_DATA
{
	LIST_ENTRY		ListEntry;
	ULONG			ParentProcessId;
	ULONG			ProcessId;
	UNICODE_STRING	usParentProcessName;
	WCHAR			wsParentProcessName[256];
}MONITOR_IEXPLORE_DATA, * PMONITOR_IEXPLORE_DATA;
*/


const int MAX_PATH = 1024;
UNICODE_STRING DEVICENAME = RTL_CONSTANT_STRING(L"\\Device\\AUACTMONDRV");
UNICODE_STRING DEVICELINK = RTL_CONSTANT_STRING(L"\\DosDevices\\AUACTMONDRV");
