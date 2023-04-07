/*======================================================================================
   FILE				: SDCloseAll.h
   ABSTRACT			: Heade file of CSDCloseAll class
   DOCUMENTS		: 
   AUTHOR			: Sandip Sanap
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 05-12-2007
   NOTE				:
   VERSION HISTORY	: 	Dec2007 : Sandip : Ported to VS2005 with Unicoe and X64 bit Compatability.		
=======================================================================================*/
#pragma once
class CSDCloseAll
{
public:
	CSDCloseAll(void);
	~CSDCloseAll(void);
	bool KillProcesses(CStringArray& arrProcesses, int iAppExeCheck = -1);
	void GetIEWithPath(CString &csIEPath);
	//bool CloseApplicationandStopService();

	CStringArray m_arrProcessToKill;
	int m_iAppExeCheck;
};
