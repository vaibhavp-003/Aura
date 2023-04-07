#pragma once
#include <string> 
using namespace std;

#ifdef _UNICODE
typedef std::wstring tstring;
#else
typedef std::string tstring;
#endif

#ifdef DOWNLOAD_BOT
const int MIN_ARGS_CNT = 2;
const int POOL_SIZE = 5;
const int BUFF_SIZE = 4096;
const int TEMP_BUFF = 2048;
const int MAX_PARTS = 7;
const int MAX_DOMAIN_POOL = 25;
const int DOMAIN_FRONTIER_TIMEOUT = 15*1000;
const int DOMAIN_FRONTIER_DOWNTIMEOUT = 10*60*1000;
const int DOMAIN_CONTROLLER_TIMEOUT = 60*1000;
const int NEW_DOMAIN_TIMEOUT = 15*1000;
const TCHAR DEFAULT_URL[] = _T("/");
const int HTTP_CONTENT_TYPE_CNT = 12;
const int EXTENLIST_COUNT = 12;
const int URL_FILTER_CNT =  5;
const int WEB_PAGE_BUFFER = 10*1024*1024;
const int KEYWORD_COUNT = 3;
const int SIZE_OF_TAG = 50;
const int FILE_INFO_LEN = 100;
const int MAX_TRY_VERSIONS = 3;
//const LPTSTR BLANKSTRING = _T("");
const int DOWNLOAD_CONTROLLER_TIMEOUT = 30000;
const int MAX_BINARY_SIZE = 1024;
const int MAX_FILE_NAME_LENGTH = 20;
const int CRAWL_DELAY = 1000; //In Milliseconds 

enum EHTTP_CONTENT_TYPE{
	eUnknown  = -1,
	eSkipCharset = 0,
	eTextHTML,
	eTextPlain,
	eBinary,
	eTextXML,
	eText,
	eImageJpeg,
	eImageIcon,
	eImage,
	eTextCSS,
	eVideo,
	eOctet
};

enum EPROTOCOL_TYPE
{
	eHTTP_PROTOCOL,
	eFTP_PROTOCOL,
	eHTTPS_PROTOCOL
};

enum ECONTEXT_MODE {
  FRONTIER_MODE,
  INDEXING_MODE,
  CONTROLLER_MODE
};

enum DISPLAY_TYPE
{
    CONSOLE_TYPE,
    WINDOW_TYPE,
    LOG_TYPE
};

enum ARG_TYPE
{
    FEED_ARG = 1,
    FEED_NAME,
    DEPTH_LEVEL,
    SHOW_LOG,
    DOWNLOAD_FILE,
    DOWNLOAD_PATH,
    THREAD_PERDOMAIN,
    FOLLOW_EXT_DOMAIN,
    LOG_PATH,
    RANGE_DOWNLOAD
};
enum FEED_TYPE
{
	NO_FEED,
    PLAIN_URL,
    FILE_FEED,
	LSP_LIST,
    XML,
	DATABASE_FEED
};

enum E_BOT_ERROR{
  INVALID_ARG,
  INIT_FAILED,
  UNKNOWN_ERR
};

enum DOMAIN_STATE
{
	DOMAIN_NOTRUNNING,
	DOMAIN_RUNNING
};

typedef enum {
	FILE_TYPE_UNKNOWN_TEXT,
	FILE_TYPE_UNKNOWN_DATA,
	FILE_TYPE_MSEXE,
	FILE_TYPE_ELF,
	FILE_TYPE_DATA,
	FILE_TYPE_POSIX_TAR,
	FILE_TYPE_OLD_TAR,
	FILE_TYPE_GZ,
	FILE_TYPE_ZIP,
	FILE_TYPE_BZ,
	FILE_TYPE_RAR,
	FILE_TYPE_ARJ,
	FILE_TYPE_MSSZDD,
	FILE_TYPE_MSOLE2,
	FILE_TYPE_MSCAB,
	FILE_TYPE_MSCHM,
	FILE_TYPE_SIS,
	FILE_TYPE_SCRENC,
	FILE_TYPE_GRAPHICS,
	FILE_TYPE_RIFF,
	FILE_TYPE_BINHEX,
	FILE_TYPE_TNEF,
	FILE_TYPE_CRYPTFF,
	FILE_TYPE_PDF,
	FILE_TYPE_UUENCODED,
	FILE_TYPE_PST,	/* Microsoft Outlook binary email folder (.pst file) */
	FILE_TYPE_HTML_UTF16,
	FILE_TYPE_RTF,

	/* bigger numbers have higher priority (in o-t-f detection) */
	FILE_TYPE_HTML, /* on the fly */
	FILE_TYPE_MAIL,  /* magic + on the fly */
	FILE_TYPE_SFX, /* foo SFX marker */
	FILE_TYPE_ZIPSFX, /* on the fly */
	FILE_TYPE_RARSFX, /* on the fly */
	FILE_TYPE_CABSFX,
	FILE_TYPE_ARJSFX,
	FILE_TYPE_NULSFT /* on the fly */
} EFILE_TYPES;

const int DOMAIN_SIZE = 200;
const int URL_SIZE = 4096;
const int LMDT_SIZE = 50;
const int ETAG_SIZE = 50;
const int MD5_SIZE = 66;

#pragma pack(1)
typedef struct tagDomainItem
{
	TCHAR szDomainName[DOMAIN_SIZE]; 
	LONGLONG uLastVisitedTime;
	DWORD dwURLCnt;
	bool bEXEFarm;
	WORD dwCategory;
	LPVOID lpDomainCntxt;
}DOMAIN_ITEM,*LPDOMAIN_ITEM;

typedef struct tagURLItem
{
	TCHAR szURLName[URL_SIZE]; 
	DWORD dwLastVisited;
	DWORD dwDepthLevel;
	DWORD dwContentLength;
	bool bReverseURL;
	DWORD dwLinksCntOnURL;
	DWORD dwDownloadedCnt;
	bool  bURLVersion;
	DWORD dwBaseVersion;
}URL_ITEM,*LPURL_ITEM;

typedef struct tagDownloadItem
{
	TCHAR szURLName[URL_SIZE]; 
	TCHAR szEXEName[MAX_BINARY_SIZE]; 
	LONGLONG lLastVisitedTime;//Crawling Time in Seconds
	TCHAR szBinLMDT[LMDT_SIZE];
	DWORD dwContentLength;
	TCHAR szETAG[ETAG_SIZE];
	TCHAR szMD5[MD5_SIZE];
	TCHAR szDomainName[DOMAIN_SIZE]; 
	DWORD dwAge;
	TCHAR szProductName[MAX_PATH];
}DOWNLOAD_ITEM,*LPDOWNLOAD_ITEM;

typedef struct tagEXEFARMITEM
{
	TCHAR szExeFarmName[DOMAIN_SIZE*2]; 
	LONGLONG uLastVisitedTime;
}EXEFARM_ITEM,*LPEXEFARM_ITEM;

typedef struct {
	size_t offset;
	const char *magic;
	size_t length;
	const char *descr;
	EFILE_TYPES type;
}FILETYPEINFO,*LPFILETYPEINFO;
#pragma pack()

#define IDS_MBOT_LOGNAME _T("MBOT.Log")
#define IDS_EXEFAMRLOG_NAME _T("MBOT_EXEFARM.Log")
#define IDS_DOWNLOADERLOG_NAME _T("MBOT_Downloader.Log")
#define IDS_DOMAINLOG_NAME _T("MBOT_Domain.Log")
#define IDS_HTMLTAGLOG_NAME _T("MBOT_HTMLTAG.Log")
#define IDS_ERRORLOG_NAME _T("MBOT_ERROR.Log")
#define IDS_HTMLCONTENTTPELOG_NAME _T("MBOT_ContentType.Log")
#define IDS_URLTitleLOG_NAME _T("MBOT_Title.Log")
#define IDS_DOWNLOAD_PATH _T("BotDownload")
#define IDS_SHUTDOWN_EVT_NAME _T("_PoolEventShutdown")

//BOT EXCEPTION
#define IDS_BOT_INITFAILED _T("Failed to Initialize the Bot")
#define IDS_INVALID_ARG _T("Invalid Arguments")
#define IDS_UNKNOWN_ERR _T("Unknown Error")
#define IDS_CONTROLLER_EVENT _T("ControllerNotifyEvent")
#define IDS_CONTROLLER_EXTDOMAIN_EVENT _T("ControllerExtDomainEvent")
#define IDS_CONTROLLER_STOPDOMAIN_EVENT _T("ControllerStopDomainEvent")
#define IDS_CONTROLLER_SHUTDOWN_EVENT _T("Controller Shutdown Event")
#define IDS_CONTROLLER_SHUT_EVENT _T("Got The Controller Shutdown Event")

//Regisry Settings
const TCHAR REG_THREAD_DOMAIN[] =		_T("ThreadPerDomain");
const TCHAR REG_SHOW_LOG[] =			_T("ShowLog");
const TCHAR REG_DOMAIN_DEPTH[] =		_T("DomainDepthLevel");
const TCHAR REG_USE_URLVERSION[] =		_T("UseURLVersion");
const TCHAR REG_DOWNLOAD_FILE[] =		_T("DownloadFile");
const TCHAR REG_DOWNLOAD_PATH[] =		_T("DownloadPath");
const TCHAR REG_FOLLOW_EXTDOMAIN[] =	_T("FollowExtDomain");
const TCHAR REG_PARALLEL_DOMAINCNT[] =	_T("ParallelDomainCount");
const TCHAR REG_CRAWL_SCHEDULE[] =		_T("CrawlSchedule");
const TCHAR REG_DOWNLOAD_MGR[] =		_T("dwDownloadMgr");
const TCHAR REG_APPLICATION_TYPE[] =		_T("ApplicationType");
const TCHAR REG_NETWORK_TYPE[] =		_T("NetworkType");
const TCHAR TARGET_DUMP_LOCATION[] =	_T("C:\\bot");

const TCHAR IDS_DOMAINFILTER_LIST[] = _T("MBOT_DOMAINFILTER.LOG");
const TCHAR IDS_URLFILTER_LIST[] = _T("MBOT_URLFILTER.LOG");
const TCHAR IDS_DOMAININCLUDED_LIST[] = _T("MBOT_INCLUDED_DOMAIN.LOG");
const TCHAR IDS_TITLEINCLUDED_LIST[] = _T("MBOT_INCLUDED_TITLE.LOG");
const TCHAR IDS_DOMAINTITLEINCLUDED_LIST[] = _T("_TITLE.LOG");

#define IDS_MBOT_DOMAINDB _T(".\\BotDomain.DB")
const TCHAR IDS_EXEFARM_DB[] = _T(".\\MBOT_EXEFARM.DB");
const TCHAR IDS_DOWNLOADITEM_DB[] = _T(".\\MBOT_DOWNLOADITEM.DB");

//Externs
extern const TCHAR HTTP_CONTENT_TYPE[HTTP_CONTENT_TYPE_CNT][50];
extern const TCHAR PROTOCOL_TYPE[KEYWORD_COUNT][50]; 
extern const TCHAR FILTER_URL_LIST[URL_FILTER_CNT][50];
extern const FILETYPEINFO filetype_info[];
extern const TCHAR EXTLIST[EXTENLIST_COUNT][50];
#else
	const int URL_SIZE = 100;
	const int LMDT_SIZE = 50;
	const int ETAG_SIZE = 50;
	const int DOMAIN_SIZE = 200;
	const int MAX_BINARY_SIZE = 40;
#endif