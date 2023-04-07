#pragma once

#define MAX_DEF_HEAP_SIZE		(10 * 1024 * 1024)
#define MAX_FILE_RECORD_SIZE	1675
#define MAX_REG_RECORD_SIZE		3776
#define MAX_FILE_RECORD_RANGE	1000000
#define MAX_REG_RECORD_RANGE	300000000

#pragma pack(1)
typedef struct
{
	DWORD	dwIndex;
	BYTE	byReportData[MAX_FILE_RECORD_SIZE];
}FILE_REPORT_DATA,*LPFILE_REPORT_DATA;

typedef struct
{
	DWORD	dwIndex;
	BYTE	byReportData[MAX_REG_RECORD_SIZE];
}REG_REPORT_DATA, * LPREG_REPORT_DATA;
#pragma pack()




class CMaxReportQMGR
{
public:
	HANDLE			m_hHeapHadle = NULL;
	HANDLE			m_hMapping = NULL;
	unsigned char*	m_pHeapBuffer = NULL;
	DWORD			m_dwHeapIncreaseCnt = 0x04;
	DWORD			m_dwCurHeapIndex = 0x00;
	DWORD			m_dwCurRecCnt = 0x01;

	BOOL	AllocateHeapMem();
	BOOL	ExtendHeapMemory();
	DWORD	AddRecordtoReportQueue(LPVOID lpBuffer, int iType);
	DWORD	GetRecordFromReportQueue(DWORD dwIndex, LPVOID lpBuffer);

	BOOL	AllocateVirtualMem();
	BOOL	AllocateMemMapFile(TCHAR *szTempFilename);
	BOOL	ExtendMapFileMemory();
	BOOL	ReleaseMemMapFile();
};

