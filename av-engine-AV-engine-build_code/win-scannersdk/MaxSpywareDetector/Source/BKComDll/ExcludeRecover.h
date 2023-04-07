#pragma once
#include "pch.h"
#include <MaxConstant.h>
#include <ExcludeDlg.h>

class CExcludeRecover
{
public:
	CExcludeRecover();
	~CExcludeRecover();

	void GetExcludedList(CS2U* pobjSpyNameToIDMap);
	void GetExcludedListEx(CS2U* pobjSpyNameToIDMap, ExcludeData* pExcludeDataArray, int iExcludeDataSize);
	int GetExcludedCount();
};
