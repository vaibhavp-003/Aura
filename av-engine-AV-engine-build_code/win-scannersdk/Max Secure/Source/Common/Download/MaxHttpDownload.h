#pragma once
#include "maxdownload.h"
#include <Winhttp.h>

class CMaxHttpDownload :
	public CMaxDownload
{
public:
	CMaxHttpDownload(void);
	virtual ~CMaxHttpDownload(void);
	BOOL Download(LPCTSTR szUrl, LPCTSTR szDestination);
private:
	//bool GetHTTPHeader(DWORD nFlags,_bstr_t &bstrHeader);
	bool InitializeHost(LPCTSTR szUrl);
	BOOL CheckHeaderForExe();

	HINTERNET m_hSession;
	HINTERNET m_hConnect;
	HINTERNET m_hRequest;
	TCHAR m_szHostName[MAX_PATH];
	TCHAR m_szMainUrl[MAX_URL_SIZE];
};
