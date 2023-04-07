#pragma once

#include <windows.h>

const ULONG Rootkit_SpyNameID = 11097;

static TCHAR szDriverLabel[]	= _T("SDAntiRtKt");
static TCHAR szDriverName[]		= _T("SDAntiRtKt.sys");
const TCHAR szRootKitWhiteDB[]	= _T("Setting\\RootKitWhiteDB.INI");

#define BOOTSECTORSIZE	512
#define MAX_DRIVES_NUM	26
#define DRIVELETTERSIZE 10

#define FAT12			0x0			  
#define FAT16			0x2			  
#define FAT32			0x4			  
#define FAT				0x8			  
#define NTFS			0xF			    
#define UNKNOWN			0x20

#define BPB3_4			0x0			    
#define BPB4_0			0x2			    
#define BPB7_0			0x4			    
#define NTBPB			0x8			    
#define UNKNOWNBPB		0xF			    

#define BPBSIGNATUREBYTE 0x29			        
#define NTBPBSIGNATUREBYTE 0x80

#define MAXFAT12CLUSTERS			4086
#define MAXFAT16CLUSTERS			65526
#define MAXFAT32CLUSTERS			16777206

#define OPERATION_SUCCESS			0x1
#define INVALID_PATH				0x2
#define PATH_DOESNOT_EXIST			0x3
#define INVALID_MEMORY				0x4
#define INSUFFICIENT_BUFFER			0x5
#define	INSUFFICIENT_MEMORY			0x6
#define END_OF_FILE					0x7
#define DISK_READ_FAILED			0x8
#define DISK_WRITE_FAILED			0x9
#define NEGATIVE_FILE_OFFSET		0xA
#define OFFSET_EXCEEDED_FILE_SIZE	0xB
#define INVALID_MOVE_METHOD			0xC
#define CREATEFILE_FAILED			0xD
#define BACKUP_FAILED				0xE
#define EXCEPTION_CAUGHT			0xF
#define VALIDBOOTSECTORSIGNATURE	0xAA55
#define NTFSSTRING					L"NTFS"
#define FAT32STRING					L"FAT32"
#define FATSTRING					L"FAT"

#define ROOTKIT_SPYNAME_ID			1000				

typedef struct MFT_DATA_RUN
{
	LONGLONG Offset;
	LONGLONG Length;
	MFT_DATA_RUN* node;
} DATA_RUN_LIST;

#define MSG_BUFF_SIZE 40960

typedef DWORD  ULONG;
typedef WORD   USHORT;
//typedef ULONG  NTSTATUS;

typedef enum _KEY_INFORMATION_CLASS 
{
	KeyBasicInformation,
	KeyNodeInformation,
	KeyFullInformation 
} KEY_INFORMATION_CLASS;

typedef struct _KEY_BASIC_INFORMATION 
{
	LARGE_INTEGER LastWriteTime;					           
	ULONG  TitleIndex;							        
	ULONG  NameLength;							         
	WCHAR  Name[MAX_PATH];     	             
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef struct _KEY_NODE_INFORMATION 
{
	LARGE_INTEGER LastWriteTime;					 
	ULONG  TitleIndex;							        
	ULONG  ClassOffset;							                      
	ULONG  ClassLength;							          
	ULONG  NameLength;							         
	WCHAR  Name[1];     	        
} KEY_NODE_INFORMATION, *PKEY_NODE_INFORMATION;

typedef struct _KEY_FULL_INFORMATION 
{
	LARGE_INTEGER  LastWriteTime;					            
	ULONG  TitleIndex;							        
	ULONG  ClassOffset;							             
	ULONG  ClassLength;							         
	ULONG  SubKeys;								        
	ULONG  MaxNameLen;							            
	ULONG  MaxClassLen;							          
	ULONG  Values;								      
	ULONG  MaxValueNameLen;						           
	ULONG  MaxValueDataLen;						            
	WCHAR  Class[1];								           
} KEY_FULL_INFORMATION , PKEY_FULL_INFORMATION ;

typedef struct _UNICODE_STRING 
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef UNICODE_STRING *PUNICODE_STRING;


typedef struct _OBJECT_ATTRIBUTES 
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;            
	PVOID SecurityQualityOfService;      
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;
typedef NTSTATUS (__stdcall *LP_NtCreateKey)
(
	HANDLE	KeyHandle, 
	ULONG	DesiredAccess, 
	POBJECT_ATTRIBUTES ObjectAttributes,
	ULONG	TitleIndex, 
	PUNICODE_STRING Class, 
	ULONG CreateOptions, 
	PULONG Disposition 
);

typedef NTSTATUS (__stdcall *LP_NtSetValueKey)
(
	IN HANDLE  KeyHandle,
	IN PUNICODE_STRING  ValueName,
	IN ULONG  TitleIndex,			  
	IN ULONG  Type,
	IN PVOID  Data,
	IN ULONG  DataSize
);

typedef NTSTATUS (__stdcall *LP_NtDeleteKey)
(
	HANDLE KeyHandle
);

typedef NTSTATUS ( NTAPI *LP_NtEnumerateKey)
(
	IN HANDLE               KeyHandle,
	IN ULONG                Index,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID               KeyInformation,
	IN ULONG                Length,
	OUT PULONG              ResultLength 
);

typedef NTSTATUS ( NTAPI * LP_NtQueryKey) 
(
	IN HANDLE               KeyHandle,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID               KeyInformation,
	IN ULONG                Length,
	OUT PULONG              ResultLength 
) ;

typedef NTSTATUS ( NTAPI * LP_NtClose) 
( 
	IN HANDLE ObjectHandle
);