#pragma once
#include "MaxConstant.h"
#include "MaxProductMerger.h"

class CMaxMergerWrapper
{
public:
	CMaxMergerWrapper(void);
	virtual ~CMaxMergerWrapper(void);

	void ProcessMessage(LPMAX_DISPATCH_MSG lpDispatchMessage, LPVOID lpVoid);

private:
	CMaxProductMerger	*m_pMaxProductMerger;
};
