#pragma once
#include <wininet.h>
#include <AfxInet.h>
#include <Windns.h>
#include <wininet.h>

#define	 MAX_CHECK_INTERNET_CONNECTION_1	_T("https://updateultraav.s3.amazonaws.com/update/checkinternet.txt")
#define	 MAX_CHECK_INTERNET_CONNECTION_2	_T("https://updateultraav.s3.amazonaws.com/update/checkinternet.txt")
#define FTP_MAX_READ_BUFFER					(64 * 1024)
#define FTP_USER_NAME						_T("cloudupload")
#define FTP_PASSWORD						_T("Mawyt12!@")
#define FTP_SERVER_NAME						_T("74.208.178.48")
#define FTP_SHARED_FILES					_T("/CLDShared")


typedef BOOL (*LPFN_REPORTER)(LPVOID lpVoid);

typedef struct _tagReporterData
{
	LPVOID	lpClass;
	int		iTotalBlocks;
	int		iStatus;
}REPORTER_DATA, *LPREPORTER_DATA;

class CMaxCLDFTP
{
public:

	CMaxCLDFTP();
	~CMaxCLDFTP();

	bool Connect();
	bool DisConnect();
	bool UploadFile(LPCTSTR szFilePath,LPCTSTR szServerFileName);
	bool UploadFileByName(LPCTSTR szFilePath, LPCTSTR szServerFileName);
	bool UploadFileByNameAndPath(LPCTSTR szFilePath, LPCTSTR szServerFilePath);
	bool Configure(LPCTSTR szServerName, LPCTSTR szUserName, LPCTSTR szPassword, LPCTSTR ServerUploadPath);

	//bool GetConfigurationDynamically(CString csURL = FTP_SERVER_ASP_PAGE);
	CString GetResponseFromASPPage(CString& csASPPage, CString csDestPath);
private:

	bool	m_bConnected;
	LPBYTE	m_byBuffer;
	HANDLE	m_hProcHeap;
	TCHAR	m_szServerName[100];
	TCHAR	m_szUserName[100];
	TCHAR	m_szPassword[100];
	TCHAR	m_szServerUploadPath[100];
	LPFN_REPORTER m_lpfnReporter;
	LPREPORTER_DATA m_lpReporterData;
	TCHAR	m_szSysDir[MAX_PATH];

	CFtpConnection*		m_pFTPCon;
	CInternetSession	m_objNetSession;

	bool CheckInternet(bool bDisplayError = false);
};