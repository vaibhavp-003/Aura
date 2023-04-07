// CUnrarDLL.h : header file
//
#include <vector>
using namespace std;
#ifndef _C_UNRARDLL_H
#define _C_UNRARDLL_H

#pragma pack(1)

#define ERAR_END_ARCHIVE        10
#define ERAR_NO_MEMORY          11
#define ERAR_BAD_DATA           12
#define ERAR_BAD_ARCHIVE        13
#define ERAR_UNKNOWN_FORMAT     14
#define ERAR_EOPEN              15
#define ERAR_ECREATE            16
#define ERAR_ECLOSE             17
#define ERAR_EREAD              18
#define ERAR_EWRITE             19
#define ERAR_SMALL_BUF          20
#define ERAR_UNKNOWN            21
#define ERAR_MISSING_PASSWORD   22

#define RAR_OM_LIST              0
#define RAR_OM_EXTRACT           1
#define RAR_OM_LIST_INCSPLIT     2

#define RAR_SKIP              0
#define RAR_TEST              1
#define RAR_EXTRACT           2

#define RAR_VOL_ASK           0
#define RAR_VOL_NOTIFY        1

#define RAR_DLL_VERSION       5

typedef struct __tagrarheader_data
{
  char         ArcName[260];
  char         FileName[260];
  unsigned int Flags;
  unsigned int PackSize;
  unsigned int UnpSize;
  unsigned int HostOS;
  unsigned int FileCRC;
  unsigned int FileTime;
  unsigned int UnpVer;
  unsigned int Method;
  unsigned int FileAttr;
  char         *CmtBuf;
  unsigned int CmtBufSize;
  unsigned int CmtSize;
  unsigned int CmtState;
}RARHEADER_DATA;
#pragma pack()

#pragma pack(1)
typedef struct __tagrarheader_data_ex
{
  char         ArcName[1024];
  wchar_t      ArcNameW[1024];
  char         FileName[1024];
  wchar_t      FileNameW[1024];
  unsigned int Flags;
  unsigned int PackSize;
  unsigned int PackSizeHigh;
  unsigned int UnpSize;
  unsigned int UnpSizeHigh;
  unsigned int HostOS;
  unsigned int FileCRC;
  unsigned int FileTime;
  unsigned int UnpVer;
  unsigned int Method;
  unsigned int FileAttr;
  char        *CmtBuf;
  unsigned int CmtBufSize;
  unsigned int CmtSize;
  unsigned int CmtState;
  unsigned int Reserved[1024];
}RARHEADER_DATA_EX;
#pragma pack()

#pragma pack(1)
typedef struct __tagraropenarchive_data
{
  char         *ArcName;
  unsigned int OpenMode;
  unsigned int OpenResult;
  char         *CmtBuf;
  unsigned int CmtBufSize;
  unsigned int CmtSize;
  unsigned int CmtState;
}RAROPENARCHIVE_DATA;
#pragma pack()

// Function pointers for accessing RAR information
typedef int	   (CALLBACK *UNRARCALLBACK)(UINT msg,LPARAM UserData,LPARAM P1,LPARAM P2);

#pragma pack(1)
typedef struct __tagraropenarchive_data_ex
{
  char         *ArcName;
  wchar_t      *ArcNameW;
  unsigned int  OpenMode;
  unsigned int  OpenResult;
  char         *CmtBuf;
  unsigned int  CmtBufSize;
  unsigned int  CmtSize;
  unsigned int  CmtState;
  unsigned int  Flags;
  UNRARCALLBACK Callback;
  LPARAM        UserData;
  unsigned int  Reserved[28];
}RAROPENARCHIVE_DATA_EX;
#pragma pack()

enum UNRARCALLBACK_MESSAGES {
  UCM_CHANGEVOLUME,UCM_PROCESSDATA,UCM_NEEDPASSWORD
};

typedef HANDLE (WINAPI *OPENARCHIVEEX)(RAROPENARCHIVE_DATA_EX *pArchiveData);
typedef int    (WINAPI *CLOSEARCHIVE)(HANDLE hArcData);
typedef int    (WINAPI *READRARHEADER)(HANDLE hArcData, RARHEADER_DATA *pHeaderData);
typedef int    (WINAPI *READRARHEADEREX)(HANDLE hArcData,RARHEADER_DATA_EX *HeaderData);
typedef int    (WINAPI *PROCESSRARFILEW)(HANDLE hArcData, int iOperation, TCHAR* strDestFolder, TCHAR* strDestName);
typedef void   (WINAPI *RARSETCALLBACK)(HANDLE hArcData,UNRARCALLBACK Callback,LPARAM UserData);

struct UNRAR_FILE {
	CString fileName;
	__int64 packSize;
	__int64 unpackSize;
};

class CUnrarDLL
{
public:
	CUnrarDLL();  
	~CUnrarDLL();
	int UnRARArchive(TCHAR *szFileName, TCHAR *szExtractedPath);

private:
	bool InitUnRARDll();
	void UnloadDLL();

	OPENARCHIVEEX m_lpOpenArchiveEx;
	CLOSEARCHIVE  m_lpCloseArchive;
	READRARHEADER m_lpReadRARHeader;
	PROCESSRARFILEW m_lpProcessRARFileW;
	READRARHEADEREX m_lpReadRARHeaderEx;
	HINSTANCE m_hUnrarDLL;
};
#endif
