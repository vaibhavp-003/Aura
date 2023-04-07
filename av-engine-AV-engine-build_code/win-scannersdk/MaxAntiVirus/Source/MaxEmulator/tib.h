#pragma once
/*
 *
 *  Copyright (C) 2010-2011 Amr Thabet <amr.thabet@student.alx.edu.eg>
 *
 *  This program is free_emu software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to Amr Thabet 
 *  amr.thabet@student.alx.edu.eg
 *
 */
/*
struct PEXCEPTION_REGISTRATION_RECORD
{
     PEXCEPTION_REGISTRATION_RECORD* Next;
     dword Handler;
};
*/

struct TIB
{
     dword ExceptionList;							//FS:[0x00]
     dword StackBase;                               //FS:[0x04]
     dword StackLimit;                              //FS:[0x08]
     dword SubSystemTib;                            //FS:[0x0C]
     dword FiberData;                               //FS:[0x10]
     dword ArbitraryUserPointer;                    //FS:[0x14]
     dword TIB1;                                    //FS:[0x18]
};
struct PEB;
struct TEB {

  dword                   EnvironmentPointer;		//+1C
  dword                   ProcessId;				//+20
  dword                   threadId;					//+24
  dword                   ActiveRpcInfo;			//+28
  dword                   ThreadLocalStoragePointer;//+2C
  dword                   Peb;						//+30
  dword                   LastErrorValue;           //+34
  dword                   CountOfOwnedCriticalSections;
  dword                   CsrClientThread;
  dword                   Win32ThreadInfo;
  dword                   Win32ClientInfo[0x1F];
  dword                   WOW32Reserved;
  dword                   CurrentLocale;
  dword                   FpSoftwareStatusRegister;
  dword                   SystemReserved1[0x36];
  dword                   Spare1;
  dword                   ExceptionCode;
  dword                   SpareBytes1[0x28];
  dword                   SystemReserved2[0xA];
  dword                   GdiRgn;
  dword                   GdiPen;
  dword                   GdiBrush;
  dword                   RealClientId1;
  dword                   RealClientId2;
  dword                   GdiCachedProcessHandle;
  dword                   GdiClientPID;
  dword                   GdiClientTID;
  dword                   GdiThreadLocaleInfo;
  dword                   UserReserved[5];
  dword                   GlDispatchTable[0x118];
  dword                   GlReserved1[0x1A];
  dword                   GlReserved2;
  dword                   GlSectionInfo;
  dword                   GlSection;
  dword                   GlTable;
  dword                   GlCurrentRC;
  dword                   GlContext;
  dword                   LastStatusValue;
  char*                   StaticUnicodeString;
  char                    StaticUnicodeBuffer[0x105];
  dword                   DeallocationStack;
  dword                   TlsSlots[0x40];
  dword                   TlsLinks;
  dword                   Vdm;
  dword                   ReservedForNtRpc;
  dword                   DbgSsReserved[0x2];
  dword                   HardErrorDisabled;
  dword                   Instrumentation[0x10];
  dword                   WinSockData;
  dword                   GdiBatchCount;
  dword                   Spare2;
  dword                   Spare3;
  dword                   Spare4;
  dword                   ReservedForOle;
  dword                   WaitingOnLoaderLock;
  dword                   StackCommit;
  dword                   StackCommitMax;
  dword                   StackReserved;
};

struct __LIST_ENTRY{
        dword              Flink;        // Ptr32 _LIST_ENTRY
        dword              Blink;       // Ptr32 _LIST_ENTRY
};

struct _LDR_DATA_TABLE_ENTRY{
  __LIST_ENTRY               InLoadOrderLinks;              //+00
  __LIST_ENTRY               InMemoryOrderLinks;            //+08
  __LIST_ENTRY               InInitializationOrderLinks;    //+10
  MAX_DWORD                 DllBase;                        //+18
  dword                     EntryPoint;                     //+1C
  dword                     SizeOfImage;                    //+20
  dword                     FullDllNameLength;              //+24
  char*                     FullDllName; // _UNICODE_STRING //+28
  dword                     BaseDllNameLength;              //+2C
  char*                     BaseDllName; //_UNICODE_STRING  //+30
  dword                     Flags;                          //+34
  short                     LoadCount;                      //+38
  short                     TlsIndex;                       //+3C
  union{
  __LIST_ENTRY               HashLinks;
  dword                     SectionPointer;
  };
  dword                     CheckSum;
  union{
    dword                   TimeDateStamp;
    dword                   LoadedImports;
  };
  dword                     EntryPointActivationContext;
  dword                     PatchInformation;
  __LIST_ENTRY               ForwarderLinks;
  __LIST_ENTRY               ServiceTagLinks;
  __LIST_ENTRY               StaticLinks;
};

struct _PEB_LDR_DATA {
    dword                 Length_;                      //+00
    dword                 Initialized;                  //+04
    dword                 SsHandle;                     //+08
    __LIST_ENTRY           InLoadOrderModuleList;       //+0C
    __LIST_ENTRY           InMemoryOrderModuleList;     //+14
    __LIST_ENTRY           InInitializationOrderModuleList;//+1C
    dword                 EntryInProgress;              //+24  
    dword                 ShutdownInProgress;           //+28
    dword                 ShutdownThreadId;             //+2C
};  //size = 30

struct PEB {
  char                    InheritedAddressSpace;			//+00
  char                    ReadImageFileExecOptions;			//+01
  char                    BeingDebugged;
  char                    Spare;
  dword                   Mutant;							//+04
  dword                   ImageBaseAddress;					//+08
  dword					  LoaderData;						//+0C
  dword                   ProcessParameters;				//+10
  dword                   SubSystemData;					//+14
  dword                   ProcessHeap;						//+18
  dword                   FastPebLock;						//+1C
  dword                   FastPebLockRoutine;				//+20
  dword                   FastPebUnlockRoutine;             //+24
  dword                   EnvironmentUpdateCount;           //+28
  dword                   KernelCallbackTable;              //+2C
  dword                   EventLogSection;                  //+30
  dword                   EventLog;                         //+34
  dword                   FreeList;                         //+38
  dword                   TlsExpansionCounter;              //+3C
  dword                   TlsBitmap;                        //+40
  dword                   TlsBitmapBits[0x2];
  dword                   ReadOnlySharedMemoryBase;
  dword                   ReadOnlySharedMemoryHeap;
  dword                   ReadOnlyStaticServerData;
  dword                   AnsiCodePageData;
  dword                   OemCodePageData;
  dword                   UnicodeCaseTableData;
  dword                   NumberOfProcessors;
  dword                   NtGlobalFlag;
  char                    Spare2[0x4];
  dword                   CriticalSectionTimeout1;
  dword                   CriticalSectionTimeout2;
  dword                   HeapSegmentReserve;
  dword                   HeapSegmentCommit;
  dword                   HeapDeCommitTotalFreeThreshold;
  dword                   HeapDeCommitFreeBlockThreshold;
  dword                   NumberOfHeaps;                   //+88
  dword                   MaximumNumberOfHeaps;            //+8C
  dword                   *ProcessHeaps;                   //+90
  dword                   GdiSharedHandleTable;
  dword                   ProcessStarterHelper;
  dword                   GdiDCAttributeList;
  dword                   LoaderLock;
  dword                   OSMajorVersion;
  dword                   OSMinorVersion;
  dword                   OSBuildNumber;
  dword                   OSPlatformId;
  dword                   ImageSubSystem;
  dword                   ImageSubSystemMajorVersion;
  dword                   ImageSubSystemMinorVersion;
  dword                   GdiHandleBuffer[0x22];
  dword                   PostProcessInitRoutine;
  dword                   TlsExpansionBitmap;
  char                    TlsExpansionBitmapBits[0x80];
  dword                   SessionId;
};
