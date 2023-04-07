/*======================================================================================
FILE             : MaxInitScanner.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Siddharam Pujari
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
CREATION DATE    : 8/1/2009 6:37:36 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "MaxCommunicator.h"
#include "MaxCommunicatorServer.h"
#include "MaxConstant.h"
#include "MaxProcessReg.h"

class CMaxInitScanner
{
public:
	CMaxInitScanner();
	~CMaxInitScanner();
	void StartScanner();
	BOOL InitScanner();

private:
	void AppCrashHandler();
	MAX_PIPE_DATA sMaxPipeData;
	MAX_PIPE_DATA_CMD sMaxPipeDataCmd;

	HANDLE	m_hGlobalMutex;
	HANDLE	m_hGlobalMutexML;
	HANDLE	m_hGlobalMutexBKG;
};