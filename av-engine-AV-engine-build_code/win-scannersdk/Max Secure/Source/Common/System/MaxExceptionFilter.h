/*======================================================================================
FILE             : MaxExceptionFilter.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshit Kasliwal
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 07/09/2009.
NOTES		     : Max Exception Filter Class for:
					1. Structured Exception
					2. Send Error Report Exception
					3. Invalid Param handler for CRT safety functions
					4. Creating Crash Dumps 
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include <excpt.h>
#include <stdlib.h>
#include <stdio.h>
#include <crtdbg.h>  // For _CrtSetReportMode

typedef void (*SEHExecProc)();

enum EXFILTER_TYPE
{
	E_INVALID_PARAM,
	E_SET_UNHANDLED_EXFILTER,
	E_ALL
};

class CMaxExceptionFilter
{
public:
	static void InitializeExceptionFilter(EXFILTER_TYPE eFilterType = E_ALL);
	static void MaxInvalidParamHandler(const wchar_t* expression, const wchar_t* function, const wchar_t* file, unsigned int line, uintptr_t pReserved);
	static int Filter(unsigned int code, struct _EXCEPTION_POINTERS *ep,LPCTSTR lpExMsg,bool bTakeDump = true);
	static int Filter(unsigned int code, struct _EXCEPTION_POINTERS *ep, LPCTSTR lpExMsg, LPCTSTR lpFileName, bool bTakeDump = true);
	static LONG MaxUnhandledExceptionFilter(PEXCEPTION_POINTERS pExcPtrs);
	static bool SEHExecuteProc(SEHExecProc fnPtrExecProc, LPCTSTR lpMsg);
	static DWORD GetErrorReportStatus();
	static _invalid_parameter_handler m_lpHandler;
	static _invalid_parameter_handler m_lpOldHandler;
private:
	static BOOL CreateMiniDump(EXCEPTION_POINTERS* pExceptionPointers);
	CMaxExceptionFilter();
	~CMaxExceptionFilter();
};
