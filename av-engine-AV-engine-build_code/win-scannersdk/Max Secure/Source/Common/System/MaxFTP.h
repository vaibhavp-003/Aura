#pragma once
#include <wininet.h>
#include <AfxInet.h>
#include <Windns.h>
#include <wininet.h>



// samples uploading to ftp server configuration.

#define FTP_SERVER_ASP_PAGE		_T("")
#define FTP_LT_SERVER_ASP_PAGE		_T("") //for Laptop Tracker
//#define FTP_SERVER_NAME			_T("123.237.68.142")
#define FTP_USER_NAME			_T("")
//#define FTP_PASSWORD			_T("=RWfy!Gn9B#Q")								
#define FTP_PASSWORD			_T("Date25381!")
#define FTP_SUBMIT_SAMPLES		_T("/SubmitSamples")
//#define FTP_THREAT_COMMUNITY	_T("/ThreatCommunity")
//#define FTP_THREAT_COMMUNITY	_T("/NewThreat")
#define FTP_THREAT_COMMUNITY	_T("/NewThreat2012")
#define FTP_SCREEN_SHOTS		_T("/Lost_laptop_pics")
#define FTP_CONTACT_BACKUP		_T("/Mobile_contact_backup")
#define FTP_EXPORT_LOG			_T("/ExportLog")
#define FTP_MAX_READ_BUFFER		(64 * 1024)

//alternative ftp server
#define FTP_SERVER_NAME_ATV		_T("")
#define FTP_USER_NAME_ATV		_T("")
#define FTP_PASSWORD_ATV		_T("")

typedef BOOL (*LPFN_REPORTER)(LPVOID lpVoid);

typedef struct _tagReporterData
{
	LPVOID	lpClass;
	int		iTotalBlocks;
	int		iStatus;
}REPORTER_DATA, *LPREPORTER_DATA;

class CMaxFTP
{
public:

	CMaxFTP();
	~CMaxFTP();

	bool Connect();
	bool DisConnect();
	bool GetServerDateTime(LPCTSTR szUniqueStr, CString& csDate, CString& csTime);
	bool SetReporter(LPFN_REPORTER lpfnReporter, LPREPORTER_DATA lpReporterData);
	bool UploadFile(LPCTSTR szFilePath);
	bool UploadFileByDate(LPCTSTR szFilePath);
	bool UploadFileByName(LPCTSTR szFilePath, LPCTSTR szServerFileName);
	bool UploadFileByNameAndPath(LPCTSTR szFilePath, LPCTSTR szServerFilePath);
	bool Configure(LPCTSTR szServerName, LPCTSTR szUserName, LPCTSTR szPassword, LPCTSTR ServerUploadPath);

	CString GetExternalIPAddress();


	bool UploadExportLogFile(LPCTSTR szFilePath, CString csMachineID);

	bool GetConfigurationDynamically(CString csURL = FTP_SERVER_ASP_PAGE);
	CString GetResponseFromASPPage(CString& csASPPage, CString csDestPath);

	bool UploadFileEx(LPCTSTR szFilePath,LPCTSTR szServerFileName);
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
	CString GetResponseFromASPPage(CString& csASPPage);
	bool GetProxyDetails(CString &csProxyServer, CString &csProxyUserName, CString &csProxyPassword);
};