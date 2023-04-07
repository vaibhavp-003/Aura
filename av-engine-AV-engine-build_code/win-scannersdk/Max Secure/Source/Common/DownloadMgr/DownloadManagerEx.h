#pragma once

//#define TOTALTHREADS	2

class CDownloadManagerEx
{
	int m_iThreadCount;
	DWORD* m_pdwFileDownloadedSize;
	static int m_iAccessType;
	BOOL GetProxyDetails(CString &csProxyServer, CString &csProxyUserName, CString &csProxyPassword);
	DWORD CheckInternet(DWORD dwAccessType);
	BOOL CheckInternetPresent(CString csSourceURL,int iAccessType, CString &csResult);
	void UpdateStatus(DWORD dwTotalSize);
public:
	static double m_dDownloadedFileSize, m_dTotalFileSize;
	int* m_piIsThreadRunning;

	CDownloadManagerEx(int iThreadCount);
	~CDownloadManagerEx();

	BOOL DownloadURL(CString csSourceURL1, CString csSourceURL2, CString csDestFile, DWORD dwTotalSize=0, CString csMD5=L"");
	CString DownloadURLContent(CString csSourceURL);
	BOOL DownloadURLUsingHTTP(CString csSourceURL, CString csDestFile, DWORD dwTotalSize=0);
	BOOL DownloadURLUsingFTP(CString csSourceURL, CString csDestFile, DWORD dwTotalSize=0);
	BOOL DownloadURLUsingHTTPInThreads(int iThreadID, CString csSourceURL, CString csDestFile, DWORD dwStartPos, DWORD dwEndPos);

	//bool IsThreadRunningTest;
};

typedef struct
{
	int iThreadID;
	CString csSourceURL;
	CString csDestFile;
	DWORD dwStartPos;
	DWORD dwEndPos;
	CDownloadManagerEx* pDownloadManagerEx;
}DownloadInfo;