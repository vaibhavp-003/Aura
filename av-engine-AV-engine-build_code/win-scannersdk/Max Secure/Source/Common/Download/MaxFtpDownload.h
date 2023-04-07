#pragma once
#include "maxdownload.h"

class CMaxFtpDownload :
	public CMaxDownload
{
public:
	CMaxFtpDownload(void);
	virtual ~CMaxFtpDownload(void);
	BOOL Download(LPCTSTR szUrl, LPCTSTR szDestination);
};
