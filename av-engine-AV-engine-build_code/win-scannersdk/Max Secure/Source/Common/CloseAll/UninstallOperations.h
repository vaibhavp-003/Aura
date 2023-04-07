#pragma once
#include "pch.h"
#include "SDCloseAll.h"
#include "Registry.h"
#include "SDSystemInfo.h"
#include "RemoteService.h"
#include "FileOperation.h"
#include "RestorePoint.h"
#include "CPUInfo.h"
#include <Atlbase.h>
#include "EnumProcess.h"
#include "MaxExceptionFilter.h"

class CUninstallOperations
{

public:
	int UnInstallationOperations(CString csCommandLine, CString csParam);
	CSystemInfo objSystemInfo;

private:
	void StopWDService();
	BOOL CloseAllExeFunction(int iExeCheck);
	BOOL PauseSDSelfProtection(bool bPause);
	void DeleteSDFiles(CString csSysPath);
	void AddProcessesInArray(CStringArray &arrProcesses);
	void QuarantineFolderRemove(CString csParam);
	int UnInstallPage(CString csParam, CString csCommandLine);

};