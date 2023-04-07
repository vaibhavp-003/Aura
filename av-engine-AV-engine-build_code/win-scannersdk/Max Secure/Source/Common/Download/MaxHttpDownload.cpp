#include "StdAfx.h"
#include "MaxHttpDownload.h"


CMaxHttpDownload::CMaxHttpDownload(void)
{
	m_hSession = NULL, 
    m_hConnect = NULL,
    m_hRequest = NULL;
}

CMaxHttpDownload::~CMaxHttpDownload(void)
{
	if (m_hRequest) WinHttpCloseHandle(m_hRequest);
    if (m_hConnect) WinHttpCloseHandle(m_hConnect);
    if (m_hSession) WinHttpCloseHandle(m_hSession);
}

bool CMaxHttpDownload::InitializeHost(LPCTSTR szUrl)
{
	URL_COMPONENTS urlComp;
	size_t nURLLen = 0; 

	wmemset(m_szMainUrl, 0, MAX_URL_SIZE);
	wmemset(m_szHostName, 0, MAX_PATH);
    
	// Initialize the URL_COMPONENTS structure.
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);

    // Set required component lengths to non-zero 
    // so that they are cracked.
    urlComp.dwSchemeLength    = -1;
    urlComp.dwHostNameLength  = -1;
    urlComp.dwUrlPathLength   = -1;
    urlComp.dwExtraInfoLength = -1;

    // Crack the URL.
    if (!WinHttpCrackUrl( szUrl, _tcslen(szUrl), 0, &urlComp))
    {
        printf("Error %u in WinHttpCrackUrl.\n", GetLastError());
		return false;
    }
	else
	{
		_tcscpy_s(m_szMainUrl, MAX_URL_SIZE, urlComp.lpszUrlPath);
        //_bstr_t strExtraInfo = urlComp.lpszExtraInfo;
        nURLLen = _tcslen(urlComp.lpszUrlPath);
		size_t nHostLen = _tcslen(urlComp.lpszHostName) - nURLLen;
        _tcsncpy_s(m_szHostName,MAX_PATH, urlComp.lpszHostName,nHostLen);
	}

	 // Use WinHttpOpen to obtain a session handle.
    m_hSession = WinHttpOpen( L"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",  
							WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
							WINHTTP_NO_PROXY_NAME, 
							WINHTTP_NO_PROXY_BYPASS, 0);

    // Specify an HTTP server.
    if (m_hSession)
    {
        m_hConnect = WinHttpConnect( m_hSession, (LPCWSTR)m_szHostName,
									INTERNET_DEFAULT_HTTP_PORT, 0);  
        
        if(m_hConnect)
        {
           return true;
        }
    }
	return false;
}
BOOL CMaxHttpDownload::CheckHeaderForExe()
{
	DWORD dwSize = 0;
    WCHAR *lpOutBuffer = NULL;
    BOOL  bResults = FALSE;

	

    // First, use WinHttpQueryHeaders to obtain the size of the buffer.
   
    WinHttpQueryHeaders( m_hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                         WINHTTP_HEADER_NAME_BY_INDEX, NULL, 
                         &dwSize, WINHTTP_NO_HEADER_INDEX);

    // Allocate memory for the buffer.
    if( GetLastError( ) == ERROR_INSUFFICIENT_BUFFER )
    {
        lpOutBuffer = new WCHAR[dwSize/sizeof(WCHAR)];

        // Now, use WinHttpQueryHeaders to retrieve the header.
        bResults = WinHttpQueryHeaders( m_hRequest, 
                                   WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                   WINHTTP_HEADER_NAME_BY_INDEX, 
                                   lpOutBuffer, &dwSize, 
                                   WINHTTP_NO_HEADER_INDEX);
    }
   

	// Print the header contents.
    if (bResults)
	{
        printf("Header contents: \n%S",lpOutBuffer);
		if(_tcsstr(lpOutBuffer, _T("application/")) != 0)
		{
			bResults = TRUE;
		}
		else
			bResults = FALSE;
	}

    // Free the allocated memory.
    delete [] lpOutBuffer;
	lpOutBuffer = NULL;

	return bResults;

}
BOOL CMaxHttpDownload::Download(LPCTSTR szUrl, LPCTSTR szDestination)
{
    BOOL  bResult = FALSE;
	DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer = NULL;

	if(!InitializeHost(szUrl))
		goto HTTP_END;
		
	// Create an HTTP request handle.
    if (m_hConnect)
        m_hRequest = WinHttpOpenRequest( m_hConnect, L"GET", m_szMainUrl, 
                                       NULL, WINHTTP_NO_REFERER, 
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       0);

    // Send a request.
    if (m_hRequest) 
        bResult = WinHttpSendRequest( m_hRequest, 
                                       WINHTTP_NO_ADDITIONAL_HEADERS,
                                       0, WINHTTP_NO_REQUEST_DATA, 0, 
                                       0, 0);

    // End the request.
    if (bResult)
        bResult = WinHttpReceiveResponse( m_hRequest, NULL);

	if (bResult)
		bResult = CheckHeaderForExe();
	if(FALSE == bResult)
		goto HTTP_END;

	//download file
	HANDLE hFile = NULL;
	hFile = CreateFile(szDestination,                // name of the write
						GENERIC_WRITE,          // open for writing
						0,                      // do not share
						NULL,                   // default security
						CREATE_ALWAYS,          // overwrite existing
						FILE_ATTRIBUTE_NORMAL,  // normal file
						NULL);                  // no attr. template
	// Keep checking for data until there is nothing left.
    do 
    {
        // Check for available data.
        dwSize = 0;
        if (!WinHttpQueryDataAvailable( m_hRequest, &dwSize))
		{
            printf( "Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
			bResult = FALSE;
			goto HTTP_END;
		}

        // Allocate space for the buffer.
        pszOutBuffer = new char[dwSize+1];
        if (!pszOutBuffer)
        {
            printf("Out of memory\n");
            dwSize=0;
			bResult = FALSE;
			goto HTTP_END;
        }
        else
        {
            // Read the Data.
            ZeroMemory(pszOutBuffer, dwSize+1);

            if (!WinHttpReadData( m_hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
			{
                printf( "Error %u in WinHttpReadData.\n", GetLastError());
				bResult = FALSE;
				goto HTTP_END;
			}
            else
			{
                printf("%s", pszOutBuffer);
				DWORD dwBytesWritten = 0;
                if( FALSE == WriteFile( hFile,           // open file handle
										pszOutBuffer,     // start of data to write
										dwSize, // number of bytes to write
										&dwBytesWritten, // number of bytes that were written
										NULL)            // no overlapped structure
										)
                {
                    _tprintf(_T("Could not write to file (error %d)\n"), GetLastError());
					if(pszOutBuffer)
					{
						delete [] pszOutBuffer;
						pszOutBuffer = NULL;
					}
					bResult = FALSE;
					goto HTTP_END;
                }
			}
        
            // Free the memory allocated to the buffer.
			if(pszOutBuffer)
			{
				delete [] pszOutBuffer;
				pszOutBuffer = NULL;
			}
        }

    } while (dwSize>0);
           
     if(hFile)
        CloseHandle(hFile);

HTTP_END:
    // Close any open handles.
    if (m_hRequest) WinHttpCloseHandle(m_hRequest);
    if (m_hConnect) WinHttpCloseHandle(m_hConnect);
    if (m_hSession) WinHttpCloseHandle(m_hSession);
	return bResult;

}
//bool CMaxHttpDownload::GetHTTPHeader(DWORD nFlags,_bstr_t &bstrHeader)
//{
//    bool bRet = false;
//    BYTE szBuffer[BUFF_SIZE]="";
//    DWORD dwSize= BUFF_SIZE;
//    BOOL bResults = WinHttpQueryHeaders( m_hRequest, 
//            nFlags,
//            WINHTTP_HEADER_NAME_BY_INDEX, 
//            szBuffer, &dwSize, 
//            WINHTTP_NO_HEADER_INDEX);
//    
//    // Print the header contents.
//    if(bResults && (dwSize > 0))
//    {
//        bstrHeader = (LPWSTR)szBuffer;
//        bRet = true;
//    }
//    return bRet;
//}