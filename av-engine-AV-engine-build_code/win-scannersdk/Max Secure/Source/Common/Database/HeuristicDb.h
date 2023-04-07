/*======================================================================================
   FILE			: HeuristicDb.h 
   ABSTRACT		: class for handling operation realted to local Heuristic db
   DOCUMENTS	: Heuristics_LocalDb Design document.DOC
   AUTHOR		: Dipali Pawar
   COMPANY		: Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE: 15-May-2008
   NOTES		:
   VERSION HISTORY	:
 ======================================================================================*/

#pragma once
#include "tbtremfc.h"
#include "SDSystemInfo.h"
#include "Crc64.h"

const CString SPY_FILE_HEURISTIC_LOCAL = _T("SdHeuristic.txt");
class CHeuristicDb
{
public:
	CHeuristicDb(void);
	~CHeuristicDb(void);

	void Save(const CString& strFileName);
	void Read(const CString& strFileName);
	void GetHeuristicInfo(const CString& csFileName, CString &csHeuristicPattern, double &iTotalWeight,DWORD nModifiedTimeHigh, DWORD nModifiedTimeLow, ULONGLONG ulSize);
	bool SetHeuristicInfo(const CString& csFileName, CString csHeuristicPattern, double iTotalWeight, DWORD nModifiedTimeHigh, DWORD nModifiedTimeLow, ULONGLONG ulSize);

private:
	CtStringToCObject m_objLocaldb;
	CCrc64 m_objCRC64;
	bool m_bChanged;

};
