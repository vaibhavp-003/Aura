#include "pch.h"
#include "MaxCertScan.h"

CMaxCertScan::CMaxCertScan(void)
{	
	m_szAppDataPath = NULL;	
	m_szLocalAppDataPath = NULL;
}

CMaxCertScan::~CMaxCertScan(void)
{
	if(m_szAppDataPath != NULL)
	{
		free(m_szAppDataPath);
	}
	m_szAppDataPath = NULL;

	if(m_szLocalAppDataPath != NULL)
	{
		free(m_szLocalAppDataPath);
	}
	m_szLocalAppDataPath = NULL;

}

void CMaxCertScan::SetAppDataPath(LPCTSTR pszAppDataPath, LPCTSTR pszLocalAppDataPath)
{
	m_szAppDataPath = (WCHAR *)malloc(MAX_PATH * sizeof(WCHAR *));
	_tcscpy(m_szAppDataPath, pszAppDataPath);
	m_szLocalAppDataPath = (WCHAR *)malloc(MAX_PATH * sizeof(WCHAR *));
	_tcscpy(m_szLocalAppDataPath, pszLocalAppDataPath);
	
}

bool CMaxCertScan::CheckBlackFileName(LPCTSTR pszFileName)
{
	if(m_szAppDataPath == NULL)
		return false;
	if(m_szLocalAppDataPath == NULL)
		return false;
	
	TCHAR	szPattern1[MAX_PATH] = {0x00}; 
	TCHAR	szPattern2[MAX_PATH] = {0x00};
	TCHAR	szPostfixExpr[] = _T("}.exe");	

	_stprintf_s(szPattern1, L"%s\\{", m_szAppDataPath);
	_stprintf_s(szPattern2, L"%s\\{", m_szLocalAppDataPath);

	if(_tcsstr(pszFileName, szPattern2) != NULL && _tcsstr(pszFileName, szPostfixExpr) != NULL)
	{
		return true;			
	}
	if(_tcsstr(pszFileName, szPattern1) != NULL && _tcsstr(pszFileName, szPostfixExpr) != NULL)
	{
		return true;			
	}

	return false;
}

bool CMaxCertScan::CheckBlackFileInAppData(LPCTSTR pszFileName)
{
	if(m_szAppDataPath == NULL)
		return false;
	if(m_szLocalAppDataPath == NULL)
		return false;
	
	TCHAR	szAppData[MAX_PATH] = {0x00};
	TCHAR	szFileName[MAX_PATH] = {0x00};
	TCHAR	szExtention[]		= _T(".exe");

	if(_tcsrchr(pszFileName, _T('\\')) == NULL)
	{
		return false;
	}

	_tcscpy(szFileName, _tcsrchr(pszFileName, _T('\\')));
	_tcsncpy(szAppData, pszFileName, _tcslen(pszFileName) - _tcslen(szFileName));
	_tcscpy(szFileName, szFileName + 1);
		
	if(_tcscmp(m_szAppDataPath, szAppData) == 0 && _tcsstr(szFileName, _T("\\")) == NULL && 
		_tcsstr(szFileName, szExtention) != NULL)
	{
		return true;
	}	
	if(_tcscmp(m_szLocalAppDataPath, szAppData) == 0 &&  _tcsstr(szFileName, _T("\\")) == NULL && 
		_tcsstr(szFileName, szExtention) != NULL)
	{
		return true;
	}
	return false;
}
