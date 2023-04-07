#include <dontuse.h>

#define MONITOR_DEFAULT_REQUEST_COUNT       1
#define MONITOR_DEFAULT_THREAD_COUNT        1
#define MONITOR_MAX_THREAD_COUNT            64
#define MONITOR_READ_BUFFER_SIZE			1024

const PWSTR MonitorPortName = L"\\MonitorPort";

#pragma pack(1)

typedef struct _MONITOR_NOTIFICATION
{
	ULONG ProcessID;
    ULONG Reserved_1;			       
	ULONG TypeOfCall;
    ULONG Reserved_2;			       
	ULONG IsIgnored;
    ULONG Reserved_3;			       
    UCHAR ProcessName[MONITOR_READ_BUFFER_SIZE];
    UCHAR Accessed_1[MONITOR_READ_BUFFER_SIZE];
    UCHAR Accessed_2[MONITOR_READ_BUFFER_SIZE];
} MONITOR_NOTIFICATION, *PMONITOR_NOTIFICATION;

typedef struct _MONITOR_REPLY
{
    BOOLEAN SafeToOpen;
} MONITOR_REPLY, *PMONITOR_REPLY;

typedef struct _MONITOR_REPLY_MESSAGE
{
    FILTER_REPLY_HEADER ReplyHeader;
    MONITOR_REPLY Reply;
} MONITOR_REPLY_MESSAGE, *PMONITOR_REPLY_MESSAGE;

typedef struct _MONITOR_THREAD_CONTEXT 
{
    HANDLE Port;
    HANDLE Completion;
	VOID *pThis;
} MONITOR_THREAD_CONTEXT, *PMONITOR_THREAD_CONTEXT;

const int CALL_TYPE_UNKNOWN			= 0;
const int CALL_TYPE_F_EXECUTE		= 1;
const int CALL_TYPE_F_CREATE		= 2;
const int CALL_TYPE_F_OPEN			= 3;
const int CALL_TYPE_F_DELETE		= 4;
const int CALL_TYPE_F_RENAME		= 5;
const int CALL_TYPE_R_CREATE		= 6;
const int CALL_TYPE_R_OPEN			= 7;
const int CALL_TYPE_R_DELETE		= 8;
const int CALL_TYPE_R_RENAME		= 9;
const int CALL_TYPE_R_SETVAL		= 10;
const int CALL_TYPE_R_DELETEVAL		= 11;
const int CALL_TYPE_D_CREATE		= 12;
const int CALL_TYPE_F_NEW_FILE		= 13;

#define  EXECUTE_RIGHTS (SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_EXECUTE | FILE_READ_DATA)
