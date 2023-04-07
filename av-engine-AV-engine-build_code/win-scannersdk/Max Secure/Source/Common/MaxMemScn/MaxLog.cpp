#include "StdAfx.h"
#include "MaxLog.h"
#include "shlwapi.h"

CMaxLog::CMaxLog(void)
{
	TCHAR	*ptrw = NULL;

	memset(m_szLogFolder,0x00,sizeof(m_szLogFolder));
	GetModuleFileName(NULL,m_szLogFolder,UTL_MAX_PATH);
	if (_tcslen(m_szLogFolder) > 0)
	{
		ptrw = _tcsrchr(m_szLogFolder,L'\\');
		if (ptrw)
		{
			*ptrw = '\0';
			ptrw = NULL;
		}
	}
	else
	{
		GetTempPath(UTL_MAX_PATH,m_szLogFolder);
	}
	_tcscat_s(m_szLogFolder,UTL_MAX_PATH,L"\\Log");
	if (PathFileExists(m_szLogFolder) == FALSE)
		CreateDirectory(m_szLogFolder,NULL);

	_tcscat_s(m_szLogFolder,UTL_MAX_PATH,L"\\MemScn.Log");
}

CMaxLog::~CMaxLog(void)
{
}

int	CMaxLog::Write2Log(LPCTSTR szData)
{
	TCHAR		szLogLine[UTL_MAX_PATH] = {0};
	TCHAR		tbuffer[9] = {0};
	TCHAR		dbuffer[9] = {0};

	_wstrtime_s(tbuffer, 9);
	_wstrdate_s(dbuffer, 9);

	_stprintf_s(szLogLine,UTL_MAX_PATH,L"[%s %s] %s\r\n",dbuffer,tbuffer,szData);
	
	FILE *pOutFile = _wfsopen(m_szLogFolder, _T("a"), 0x40);
	if (pOutFile != NULL)
	{
		fputws(szLogLine, pOutFile);
		fclose(pOutFile);
	}
	return 0;
}

