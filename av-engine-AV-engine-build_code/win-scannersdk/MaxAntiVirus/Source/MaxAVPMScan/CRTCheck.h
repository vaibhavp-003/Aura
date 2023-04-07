/*======================================================================================
FILE				: CRTCheck.h
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
#pragma once
#include <crtdbg.h>
class CCRTCheck
{
public:
	CCRTCheck(void);
	~CCRTCheck(void);
	void InitializeCRTCheck();
	void CheckMemory();
};
