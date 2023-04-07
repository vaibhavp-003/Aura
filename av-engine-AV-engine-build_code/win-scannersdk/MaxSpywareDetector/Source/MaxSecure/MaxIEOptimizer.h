#pragma once
#include "MaxConstant.h"

class CMaxIEOptimizer
{
public:
	CMaxIEOptimizer(void);
	~CMaxIEOptimizer(void);

	void ProcessMessage(LPMAX_DISPATCH_MSG lpDispatchMessage, LPVOID lpVoid);
	bool IEOptimize(LPIO_MAX_PIPE_DATA lpIOMaxPipeData);
	bool IERollBack(LPIO_MAX_PIPE_DATA lpIOMaxPipeData);

	SENDVOIDMESSAGETOUI	m_pSendVoidMessageToUI;

	void SetSendMessage(SENDVOIDMESSAGETOUI pSendVoidMessageToUI)
	{
		m_pSendVoidMessageToUI = pSendVoidMessageToUI;
	}

private:
	typedef bool (__cdecl *SETALLPROPERTIES)(bool, bool, bool, bool, bool, bool, bool, bool, bool, bool);
	typedef bool (__cdecl *CLEARINDEXDAT)();
	SETALLPROPERTIES m_fnSetAllProperties;
	CLEARINDEXDAT m_fnClearIndexDatFile;
	HMODULE m_hIEOptimizeDll;

};
