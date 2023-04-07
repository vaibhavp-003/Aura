/*======================================================================================
FILE             : SplSpyConstants.h
ABSTRACT         :
DOCUMENTS	     :
AUTHOR		     :
COMPANY		     : Aura 
COPYRIGHT(NOTICE):
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be
				  used, copied, reproduced, transmitted, or stored in any form or by any
				  means, electronic, recording, photocopying, mechanical or otherwise,
				  without the prior written permission of Aura.

CREATION DATE    : 5/23/09
NOTES		     : Special spyware constants
VERSION HISTORY  :
======================================================================================*/
#pragma once
#include "bcrypt.h"
typedef DWORD  ULONG;
typedef WORD   USHORT;
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

