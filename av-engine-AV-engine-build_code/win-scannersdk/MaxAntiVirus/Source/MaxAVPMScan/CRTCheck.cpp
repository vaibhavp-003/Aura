/*======================================================================================
FILE				: CRTCheck.cpp
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 25 Jun 2010
NOTES				: This module is for checking integrity of memory at debug level
VERSION HISTORY		: 
=====================================================================================*/
#include "pch.h"
#include "CRTCheck.h"

/**********DECLARE THIS IN EVERY CPP FILE*************************/
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif
/******************************************************************/

CCRTCheck::CCRTCheck(void)
{

}

CCRTCheck::~CCRTCheck(void)
{
	
}

void CCRTCheck::InitializeCRTCheck()
{
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_CRT_DF);
	_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);
}

void CCRTCheck::CheckMemory()
{
	_CrtCheckMemory(); // Reports the problem without file/line info at first (bad), but if you hit 
	_CrtDumpMemoryLeaks();
}