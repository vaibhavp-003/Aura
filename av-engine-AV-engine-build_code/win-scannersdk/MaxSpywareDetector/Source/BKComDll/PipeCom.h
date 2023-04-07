#pragma once
#include "MaxPipes.h"
#include "MaxCommunicator.h"
#include "MaxCommunicatorServer.h"
class CPipeCom
{
public:
	bool CreateComServer(CString csPipeName);
	bool CreateUIComServer();
	bool CreateComClient(CString csPipeName, LPVOID lpParam, bool bWait =false);
	static void				OnDataReceivedCallBack(LPVOID sMaxPipeData);
	bool PostMessageToProtection(WPARAM wParam, LPARAM lParam);
	bool PostMessageToService(int iType, int iStatus);
	bool PostMessageToWSCSrv(WPARAM wParam, LPARAM lParam);
};

