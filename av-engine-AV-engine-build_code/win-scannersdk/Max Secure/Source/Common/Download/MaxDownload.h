#pragma once

enum ECONTENT_TYPE {
    CONTENT_OCTECTSTREAM,
    CONTENT_ZIP,
    CONTENT_TEXTHTML,
    CONTENT_TEXTJS,
    CONTENT_UNKNOWN
};
enum EDOWNLOAD_STATUS
{
   E_DOWNLOADNOW,
   E_DOWNLOADING,
   E_DOWNLOADDED 
};

const int MAX_URL_SIZE		= 4096;
class CMaxDownload
{
public:
	CMaxDownload(void);
	~CMaxDownload(void);
	virtual BOOL Download(LPCTSTR szUrl, LPCTSTR szDestination) = 0;
};
