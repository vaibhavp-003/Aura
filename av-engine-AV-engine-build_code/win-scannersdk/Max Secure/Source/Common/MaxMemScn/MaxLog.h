#pragma once
#include <TCHAR.H>
#include <stdio.h>
#include "MaxUtlConsts.h"

class CMaxLog
{
private:
	TCHAR		m_szLogFolder[UTL_MAX_PATH];

public:
	CMaxLog(void);
	~CMaxLog(void);
	int	Write2Log(LPCTSTR szData);
};
