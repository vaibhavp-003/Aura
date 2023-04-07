/*======================================================================================
   FILE				: CookieMonitor.h
   ABSTRACT			: Module for active protection of Cookie's
   DOCUMENTS		: 
   AUTHOR			: Darshan Singh Virdi
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 30 Apr 2008
   NOTES			: 
   VERSION HISTORY	: 
=====================================================================================*/

#pragma once
#include "ActiveMonitor.h"
#include "S2U.h"
#include "S2S.h"

class CCookieMonitor : public CActiveMonitor
{
public:
	CCookieMonitor(void);
	virtual ~CCookieMonitor(void);

	bool StartMonitor();
	bool StopMonitor();
	bool HandleExisting();

	CS2S m_objAvailableUsers;

private:
	CS2U m_objCookieDB;

	void CleanUp();
	bool SetPrivacyAdvancedOn();
};
