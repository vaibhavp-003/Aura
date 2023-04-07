#pragma once
#include "MaxConstant.h"

class CMaxLiveUpdateWrapper
{
public:
	CMaxLiveUpdateWrapper(void);
	virtual ~CMaxLiveUpdateWrapper(void);

	void ProcessMessage(LPMAX_DISPATCH_MSG lpDispatchMessage, LPVOID lpVoid);

};
