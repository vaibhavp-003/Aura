/*======================================================================================
FILE             : DirStreamStruct.h
ABSTRACT         : structures required in reading dir stream object of ole file format
DOCUMENTS	     : 
AUTHOR		     : Sourabh Kadam
CREATION DATE    : 07/10/2010
NOTES		     : 
VERSION HISTORY  : 0.0.0.0
======================================================================================*/

#pragma once
#pragma pack (1)
#include <vector>
using namespace std;
typedef struct _tagPROJECTSYSKIND
{
	WORD	Id;
	DWORD	Size;
	DWORD	SysKind;
}ProjectSysKind;

typedef struct _tagPROJECTLCID
{
	WORD	Id;
	DWORD	Size;
	DWORD	Lcid ;
}ProjectCid ;

typedef struct _tagPROJECTLCIDINVOKE
{
	WORD	Id;
	DWORD	Size;
	DWORD	LcidInvoke ;
}ProjectlCidInvoke ;

typedef struct _tagPROJECTCODEPAGE
{
	WORD	Id;
	DWORD	Size;
	WORD	CodePage ;
}ProjectCodePage ;

typedef struct _tagPROJECTNAME
{
	WORD	Id;
	DWORD	SizeOfProjectName ;
	LPBYTE	ProjectName ;
}ProjectName ;

typedef struct _tagPROJECTDOCSTRING
{
	WORD	Id;
	DWORD	SizeOfDocString ;
	LPBYTE	DocString ;
	WORD	Reserved ;
	DWORD	SizeOfDocStringUnicode ;
	LPBYTE	DocStringUnicode ;
}ProjectDocString ;

typedef struct _tagPROJECTHELPFILEPATH
{
	WORD	Id ;
	DWORD	SizeOfHelpFile1 ;
	LPBYTE	HelpFile1 ;
	WORD	Reserved ;
	DWORD	SizeOfHelpFile2 ;
	LPBYTE	HelpFile2 ;
}ProjectHelpFilePath ;

typedef struct _tagPROJECTHELPCONTEXT
{
	WORD	Id ;
	DWORD	Size ;
	DWORD	HelpContext ;
}ProjectHelpContext ;

typedef struct _tagPROJECTLIBFLAGS
{
	WORD	Id ;
	DWORD	Size ;
	DWORD	ProjectLibFlags ;
}ProjectLibFlags ;

typedef struct _tagPROJECTVERSION
{
	WORD	Id ;
	DWORD	Reserved ;
	DWORD	VersionMajor ;
	WORD	VersionMinor ;
}ProjectVersion ;

typedef struct _tagPROJECTCONSTANTS
{
	WORD	Id ;
	DWORD	SizeOfConstants ;
	LPBYTE	Constants ;
	DWORD	Reserved ;
	DWORD	SizeOfConstantsUnicode ;
	LPBYTE	ConstantsUnicode ;
}ProjectConstants ;

typedef struct _tagPROJECTINFORMATION 
{
	ProjectSysKind			SysKindRecord ;
	ProjectCid				LcidRecord ;
	ProjectlCidInvoke		LcidInvokeRecord ;
	ProjectCodePage			CodePageRecord ;
	ProjectName				NameRecord ;
	ProjectDocString 		DocStringRecord ;
	ProjectHelpFilePath		HelpFilePathRecord ;
	ProjectHelpContext		HelpContextRecord ;
	ProjectLibFlags			LibFlagsRecord ;
	ProjectVersion			VersionRecord ;
	ProjectConstants		ConstantsRecord ;
}ProjectInformation ;

/**************************************************************************************************************/

typedef struct _tagREFERENCENAME
{
	WORD	Id ;
	DWORD	SizeOfName ;
	LPBYTE	Name;
	WORD	Reserved ;
	DWORD	SizeOfNameUnicode ;
	LPBYTE	NameUnicode ;
}ReferenceName ;

typedef struct _tagREFERENCE
{
	ReferenceName	NameRecord ;
	LPBYTE	ReferenceRecord ;
}Reference ;

typedef struct _tagREFERENCEORIGINAL
{
	WORD	Id ;
	DWORD	SizeOfLibidOriginal ;
	LPBYTE	LibidOriginal ;
}ReferenceOriginal ;

typedef struct _tagREFERENCECONTROL
{
	ReferenceOriginal	OriginalRecord ;
	WORD				Id ;
	DWORD				SizeTwiddled ;
	DWORD				SizeOfLibidTwiddled ;
	LPBYTE				LibidTwiddled ;
	DWORD				Reserved1 ;
	WORD				Reserved2 ;
	ReferenceName 		NameRecordExtended ;
	WORD				Reserved3 ;
	DWORD				SizeExtended ;
	DWORD				SizeOfLibidExtended ;
	LPBYTE				LibidExtended ;
	DWORD				Reserved4 ;
	WORD				Reserved5 ;
	GUID				OriginalTypeLib;
	DWORD				Cookie ;
}ReferenceControl ;

typedef struct _tagREFERENCEREGISTERED
{
	WORD	Id;
	DWORD	Size;
	DWORD	SizeOfLibid ;
	LPBYTE	Libid ;
	DWORD	Reserved1 ;
	WORD	Reserved2 ;
}ReferenceRegistered;

typedef struct _tagREFERENCEPROJECT
{
	WORD	Id;
	DWORD	Size;
	DWORD	SizeOfLibidAbsolute ;
	LPBYTE	LibidAbsolute ;
	DWORD	SizeOfLibidRelative ;
	LPBYTE	LibidRelative ;
	DWORD	MajorVersion ;
	WORD	MinorVersion ;
	
}ReferenceProject  ;

typedef struct _tagPROJECTREFERENCES 
{
	Reference	ReferenceArray ;
}ProjectReferences ;

/****************************************************************************************************************/

typedef struct _tagPROJECTCOOKIE
{
	WORD	Id ;
	DWORD	Size ;
	WORD	Cookie ; 
}ProjectCookie;

typedef struct _tagMODULENAME
{
	WORD	Id ;
	DWORD	SizeOfModuleName ;
	LPBYTE	ModuleName ;
}ModuleName;

typedef struct _tagMODULENAMEUNICODE
{
	WORD	Id ;
	DWORD	SizeOfModuleNameUnicode ;
	LPBYTE	ModuleNameUnicode ;
}ModuleNameUnicode;

typedef struct _tagMODULESTREAMNAME
{
	WORD	Id ;
	DWORD	SizeOfStreamName ;
	LPBYTE	StreamName ;
	WORD	Reserved ;
	DWORD	SizeOfStreamNameUnicode ;
	LPBYTE	StreamNameUnicode ;
}ModuleStreamName;

typedef struct _tagMODULEDOCSTRING
{
	WORD	Id ;
	DWORD	SizeOfDocString ;
	LPBYTE	DocString ;
	WORD	Reserved ;
	DWORD	SizeOfDocStringUnicode ;
	LPBYTE	DocStringUnicode ;
}ModuleDocString;

typedef struct _tagMODULEOFFSET
{
	WORD	Id ;
	DWORD	Size ;
	DWORD	TextOffset ;
}ModuleOffset;

typedef struct _tagMODULEHELPCONTEXT
{
	WORD	Id ;
	DWORD	Size ;
	DWORD	HelpContext ;
}ModuleHelpContext;

typedef struct _tagMODULECOOKIE
{
	WORD	Id ;
	DWORD	Size ;
	WORD	Cookie ;
}ModuleCookie ;

typedef struct _tagMODULETYPE
{
	WORD	Id ;
	DWORD	Reserved ;
}ModuleType ;

typedef struct _tagMODULEREADONLY 
{
	WORD	Id ;
	DWORD	Reserved ;
}ModuleReadonly;

typedef struct _tagMODULEPRIVATE
{
	WORD	Id ;
	DWORD	Reserved ;
}ModulePrivate;

//typedef struct _TAG
//typedef struct _tag
typedef struct _tagMODULE
{
	ModuleName			NameRecord ;
	ModuleNameUnicode  	NameUnicodeRecord ;
	ModuleStreamName	StreamNameRecord ;
	ModuleDocString		DocStringRecord ;
	ModuleOffset		OffsetRecord ;
	ModuleHelpContext	HelpContextRecord ;
	ModuleCookie		CookieRecord;
	ModuleType			TypeRecord ;
	ModuleReadonly		ReadOnlyRecord ;
	ModulePrivate		PrivateRecord ;
	WORD				Terminator ;
	DWORD				Reserved ;
}StructModule;

typedef struct _tagPROJECTMODULES
{
	WORD			Id;
	DWORD			Size;
	WORD			Count;
	ProjectCookie	ProjectCookieRecord;
	StructModule	**Modules1;
	StructModule	Modules;
}ProjectModules;

typedef struct _tagDIRSTREAM
{	
	ProjectInformation	InformationRecord ;
	ProjectReferences	ReferencesRecord ;
	ProjectModules		ModulesRecord ;
	WORD Terminator;
	DWORD Reserved;
}DIR_STREAM;

typedef struct vba_version_tag
{
	unsigned char signature[4];
	const char *name;
	int vba_version;
	int is_mac;
} vba_version_t;

typedef struct _xlbof
{
   char bofMarker; // Should be 0x09

   char vers;  // Version indicator for biff2, biff3, and biff4
               // = 0x00 -> Biff2
               // = 0x02 -> Biff3
               // = 0x04 -> Biff4
               // = 0x08 -> Biff5/Biff7/Biff8

   char skip[2]; // Unspecified

   short int vers2;  // Version number
                     // 0x0500 -> Biff5/Biff7
                     // 0x0600 -> Biff8

   short int dt;     // Substream type (not used in this example)

   short int rupBuild;  // Internal build identifier
   short int rupYear;   // Internal Build year
} XLBOF;

// Word's File-Information-Block (FIB) structure...
typedef struct _fib
{
      short magicNumber;
      // Word 6.0: 0xA5DC
      // Word 7.0 (95): 0xA5DC
      // Word 8.0 (97): 0xA5EC

      short version;   // &gt;= 101 for Word 6.0 and higher...
      // Word 6.0: 101
      // Word 7.0 (95): 104
      // Word 8.0 (97): 105
}FIB, *LPFIB;

typedef struct _tagMACROS
{
	DWORD		dwSizeOfMacro;
	LPBYTE		pbyMacBuff;
	char		pStreamName[260];
}Macros;
#pragma pack ()
