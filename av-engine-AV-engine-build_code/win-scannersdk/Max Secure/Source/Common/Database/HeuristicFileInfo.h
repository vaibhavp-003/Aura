/*======================================================================================
   FILE			: HeuristicInfo.h 
   ABSTRACT		: Serialize class. To store file information like heuristicpattern, threateweight,
				  date time 
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

class CHeuristicFileInfo: public CObject
{
public:
	DECLARE_SERIAL(CHeuristicFileInfo)
	CHeuristicFileInfo(void);
	~CHeuristicFileInfo(void);
	void Serialize(CArchive &archive);

	CString		m_csHeuristicPattern;
	double		m_dTotalWeight;
	DWORD		m_dwHighDateTime;
	DWORD		m_dwLowDateTime;
	ULONGLONG	m_ulSize;		 
};
