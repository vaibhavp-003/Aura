
/*======================================================================================
FILE             : DirStream.h
ABSTRACT         : structures required in reading dir stream object of ole file format
DOCUMENTS	     : 
AUTHOR		     : Anand Srivastava
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 5/15/2009
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#pragma once

typedef struct _tagDECOMPRESSIONSTATES
{
	DWORD	CompressedRecordEnd;
	DWORD	CompressedCurrent;
	DWORD	CompressedChunkStart;
	DWORD	CompressedEnd;
	DWORD	DecompressedCurrent;
	DWORD	DecompressedBufferEnd;
	DWORD	DecompressedChunkStart;
	DWORD	DecompressedEnd;
}DecompressionStates;

typedef struct _tagCOMPRESSEDCHUNK
{
	WORD	Header;
	LPBYTE	Data;
}CompressedChunk;


typedef struct _tagDIRINFOSYSKIND
{
	WORD	Id;
	DWORD	Size;
	DWORD	SysKind;
}DirInfoSysKind;

typedef struct _tagDIRLCID
{
	WORD	Id;
	DWORD	Size;
	DWORD	LcId;
}DirLcId;

typedef struct _tagDIRLCIDINVOKE
{
	WORD	Id;
	DWORD	Size;
	DWORD	LcIdInvoke;
}DirLcIdInvoke;

typedef struct _tagDIRCODEPAGE
{
	WORD	Id;
	DWORD	Size;
	WORD	CodePage;
}DirCodePage;

typedef struct _tagCONSTOLEDIRSTREAMINFORMATION
{
	DirInfoSysKind	SysKind;
	DirLcId			LcId;
	DirLcIdInvoke	LcIdInvoke;
	DirCodePage		CodePage;
}ConstOleDirStreamInfo;

typedef struct _tagDIRNAME
{
	WORD	Id;
	DWORD	SizeOfName;
	LPBYTE	Name;
}DirName;

typedef struct _tagDIRDOCSTRING
{
	WORD	Id;
	DWORD	SizeOfDocString;
	LPBYTE	DocString;
	WORD	Reserved;
	DWORD	SizeOfDocStringUnicode;
	LPBYTE	DocStringUnicode;
}DirDocString;

typedef struct _tagDIRHELPFILEPATH
{
	WORD	Id;
	DWORD	SizeOfHelpFile1;
	LPBYTE	HelpFile1;
	WORD	Reserved;
	DWORD	SizeOfHelpFile2;
	LPBYTE	HelpFile2;
}DirHelpFilePath;

typedef struct _tagDIRHELPCONTEXT
{
	WORD	Id;
	DWORD	Reserved;
	DWORD	HelpContext;
}DirHelpContext;

typedef struct _tagDIRLIBFLAGS
{
	WORD	Id;
	DWORD	Size;
	DWORD	LibFlags;
}DirLibFlags;

typedef struct _tagDIRVERSION
{
	WORD	Id;
	DWORD	Reserved;
	DWORD	VersionMajor;
	WORD	VersionMinor;
}DirVersion;

typedef struct _tagDIRCONSTANTS
{
	WORD	Id;
	DWORD	SizeOfConstants;
	LPBYTE	Constants;
	WORD	Reserved;
	DWORD	SizeOfConstantsUnicode;
	LPBYTE	ConstantsUnicode;
}DirConstants;

typedef struct _tagVAROLEDIRSTREAMINFORMATION
{
	DirName			*	Name;
	DirDocString	*	DocString;
	DirHelpFilePath	*	HelpFilePath;
	DirHelpContext	*	HelpContext;
	DirLibFlags		*	LibFlags;
	DirVersion		*	Version;
	DirConstants	*	Constants;
}VarOleDirStreamInfo;
