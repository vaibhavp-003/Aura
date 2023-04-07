/*======================================================================================
FILE             : MaxProcessReg.h
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
CREATION DATE    : 6/26/2009.
NOTES		     : Class is used for performing the Watchdog Regisration Process for all
                   client apps
VERSION HISTORY  : 
======================================================================================*/
#pragma once
extern TCHAR *szMaxProcessName[12];
#include "MaxConstant.h"
#include "MaxCommunicator.h"
enum REGISTRATION_TYPE
{
	EACTMON_REG,
	EIOCTL_REG,
	EWD_REG,
	ALL_REG
};

class CMaxProcessReg
{
public:
	// Constructor
	CMaxProcessReg(REGISTRATION_TYPE RegType);
	// Destructor
	~CMaxProcessReg();
	// Member Functions
	bool WDRegisterProcess(E_TRUSTPID eProcessType, int nMessageInfo,CMaxCommunicator *pobjWatchDog, int nActionInfo = -1, LPCTSTR szActionPipeName = NULL);
	bool IsRegisteredWithWatchDog(){ return m_bWDRegistered;}
private:
	bool m_bWDRegistered;
	REGISTRATION_TYPE m_eRegType;
	DWORD m_controlbuff[10];
};
