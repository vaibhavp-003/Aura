/*======================================================================================
   FILE			: SockStructures.h
   ABSTRACT		: Socket Structures
   DOCUMENTS	: 
   AUTHOR		: Darshan Singh Virdi 
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
   CREATION DATE: 25/12/2003
   VERSION		: 
======================================================================================*/

#include "stdafx.h"

const int PORT_SCAN_OPTION		= 7000; //for sacnning 
const int PORT_SCHEDULE_INFO	= 7001; // Schedule machines 
const int PORT_FILE_TRANSFER	= 7003; // Copying file to and from server
const int PORT_VERSION_INFO		= 7004; // Set or get version info
const int PORT_WORM_PROCESS		= 7005; // Perform operation on spywares
const int PORT_OPTION_TYPE		= 7006; // Sending different types of msges like enable active protection
const int PORT_MESSAGE			= 7008; // Not implemented
const int PORT_PRODUCT_SETTINGS = 7009; // Not required for corporate
const int PORT_MAX_SHIELD		= 7010; // Not required for corporate 
const int PORT_REGISTRY_FIX		= 7011; // Not required for corporate

#define WSA_VERSION				  MAKEWORD(2,0)
enum ENUM_SCAN_DATA
{
	ENUM_SCAN_STATUS_INT,
	ENUM_SCAN_STATUS_CHAR,
	ENUM_SCAN_WORM_FOUND,
	ENUM_SCAN_INSPECTED_WORM_RESULT
};

enum ENUM_WORM_STATUS				//Enum for spy operation at the time of scanning
{
	LOGONLY,						// Get log only
	DELETION,						// Delete spy as sonn as found
	QUARANTINE,						// Quarantine spy 
	RECOVER,						// Recover spy
	QDELETE
};

/***************************************
 structure for scanning option
 ***************************************/
typedef	struct
{
	bool bScanType;						// false = Quick scan; true = Full scan
	bool bSignatureScan;				// true = Using Signature; false = without using signature
	ENUM_WORM_STATUS enum_Worm_Status;	// enum for scan log	
	CHAR strMachineName[MAX_PATH]; 
}SCAN_OPTION;

const int SIZE_OF_SCAN_OPTION			= sizeof(SCAN_OPTION);
const int BUF_SIZE_WORM_NAME			= 256;
const int BUF_SIZE_WORM_ENTRY			= 256;
const int BUF_SIZE_ZIP_FILE				= 256;
const int BUF_SIZE_MAX_DATA				= 1024;
#define TRANSFER_BUFFER_SIZE		8192

/***************************************
 structure for worm operation
****************************************/
// Enum for worm type
enum ENUM_WORMTYPE
{
	ENUM_WT_FILEWORM,						// files
	ENUM_WT_FOLDER,							// Folder
	ENUM_WT_PROCESSES,						// Processes
	ENUM_WT_COOKIE,							// Cookies
	ENUM_WT_REGVAL,							// Registry value
	ENUM_WT_REGDATA,						// Registry data
	ENUM_WT_REGKEY,							// Registry key
	ENUM_WT_MOZILLACOOKIE,					// Mozilla cookie
	ENUM_WT_APPINIT,						// AppInit
	ENUM_WT_SERVICES,						// Services
	ENUM_WT_NOTIFY,							// Notify
	ENUM_WT_REGDATAFIX,						// Registry data fix	
	ENUM_WT_REGVALFIX,						// Registry value fix
	ENUM_WT_ROOTKIT,						// RootKit
	ENUM_WT_NOTHING,
	ENUM_WT_SPECIALSPYWARE,					// Special Spyware
	ENUM_WT_NETWORK_CONNECTION,				// Network Connection
	ENUM_WT_MEMORY,							// Memory modules
	ENUM_WT_VIRUS							// Virus Scanner
};

typedef	struct
{
	DWORD dwSizeOfData;
	BYTE byRawData[TRANSFER_BUFFER_SIZE];
}COMM_RAW_DATA_WRITE;
const int SIZE_OF_COMM_RAW_DATA_WRITE = sizeof(COMM_RAW_DATA_WRITE);

typedef	struct
{
	DWORD dwCollectedLen;
	DWORD dwRemainingLen;
	BYTE byRawData[SIZE_OF_COMM_RAW_DATA_WRITE];
}COMM_RAW_DATA_READ;
const int SIZE_OF_COMM_RAW_DATA_READ = sizeof(COMM_RAW_DATA_READ);

typedef	struct
{
	unsigned int iScanStatusMsgID;		// 
	WPARAM		 wParam;				// 
	LPARAM		 lParam;				// 
}SCAN_STATUS_INT;
const int SIZE_OF_SCAN_STATUS_INT		= sizeof(SCAN_STATUS_INT);

typedef	struct
{
	unsigned int iScanStatusMsgID;		// 
	BYTE szwParam[BUF_SIZE_WORM_ENTRY];	// buffer containing either SCAN_STATUS or WORM_FOUND
}SCAN_STATUS_CHAR;
const int SIZE_OF_SCAN_STATUS_CHAR		= sizeof(SCAN_STATUS_CHAR);

typedef struct
{
    ENUM_WORMTYPE		enum_wormType;		// enum for worm type
    ENUM_WORM_STATUS	enum_Worm_Status;	// enum for spy operation
	BYTE strWormName[BUF_SIZE_WORM_NAME];	// Worm name		
	BYTE strWorm[BUF_SIZE_WORM_ENTRY];		// Path of worm
}SCAN_WORM_FOUND;
const int SIZE_OF_SCAN_WORM_FOUND		= sizeof(SCAN_WORM_FOUND);

typedef struct
{
    ENUM_WORMTYPE		enum_wormType;		// enum for worm type
    ENUM_WORM_STATUS	enum_Worm_Status;	// enum for spy operation
	BYTE strWormName[BUF_SIZE_WORM_NAME];	// Worm name		
	BYTE strWorm[BUF_SIZE_WORM_ENTRY];		// Path of worm
	BYTE strInputZipFileName[BUF_SIZE_ZIP_FILE];
}SCAN_WORM_PROCESS;
const int SIZE_OF_SCAN_WORM_PROCESS		= sizeof(SCAN_WORM_PROCESS);

typedef struct 
{
	unsigned int iScanStatusMsgID;	
	unsigned int iCookiesInspected;
	unsigned int iProcessInspected;
	unsigned int iFilesInspected;
	unsigned int iRegistryInspected;
	unsigned int iWormsFound;
	unsigned int iSpecialWormsFound;
}SCAN_INSPECTED_WORM_RESULTS;
const int SIZE_OF_SCAN_INSPECTED_WORM_RESULTS	= sizeof(SCAN_INSPECTED_WORM_RESULTS);

typedef struct
{
	ENUM_SCAN_DATA enum_ScanData;			// Type of structure 
	BYTE szBuffer[BUF_SIZE_MAX_DATA];		// buffer contains SCAN_STATUS_INT or SCAN_STATUS_CHAR or SCAN_WORM_FOUND
}SCAN_DATA;



const int SIZE_OF_SCAN_DATA				= sizeof(SCAN_DATA);
const int BUF_SIZE_DRIVE = 256;

/*******************************************
structure for scheduling option
********************************************/
typedef struct
{
	DWORD dwWormStatus;						// enum for scan log
	DWORD dwScanType;						// false = Quick scan; true = Full scan
	DWORD dwSignatureScan;					// true = Using Signature; false = without using signature	
	DWORD dwSelectedDay;	                // Select day i.e. from Monday to Sunday for weekly scan
	DWORD dwHour;
	DWORD dwMinute;
	DWORD dwHoursOrMins;
	DWORD dwNextSchHr ;
	DWORD dwNextSchMin ;
	DWORD dwNextSchDay ;
	DWORD dwNextSchYear ;
	DWORD dwNextSchMonth ;

}SCHEDULE_INFO;
const int SIZE_OF_SCHEDULE_INFO			= sizeof(SCHEDULE_INFO);

typedef struct
{
	DWORD dwEnableSchedule;							// Enable Schedule = true Otherwise = false
	BYTE  btScheduleInfo[SIZE_OF_SCHEDULE_INFO];	// SCHEDULE Info Structure NULL in case of Remove Schedule
}SCHEDULE_STATUS_INFO;
const int SIZE_OF_SCHEDULE_STATUS_INFO  = sizeof(SCHEDULE_STATUS_INFO);

/******************************************
 struct for version information
 ******************************************/
typedef struct
{
	int iClientVersion;					// Client version number
	int iDatabaseVersion;				// Database version number
	bool bCheckDatabaseVersion;			// True to check database version and false for client version	
}VERSION_INFO;


/******************************************
 struct for File Transfer
 ******************************************/
// Enum for which struct to send in outer struct
enum ENUM_FILE_TRANSFER
{
	ENUM_FT_FILE_INFO,			// Enum for file info structure
	ENUM_FT_FILE_DATA,			// Enum for file data structure
	ENUM_FT_FILE_EOF_DATA,		// Enum for indicating end of File data for the current file
	ENUM_FT_FILE_EOF_FILES,		// Enum for indicating end of File to be send accross
	ENUM_FT_FILE_GET_ALL_LOG,	// Enum for indicating to start sending all log files	
	ENUM_FT_FILE_GET_EXCLUDE_DB,	// Enum for indicating to start sending exclude db
	ENUM_FT_FILE_GET_VERSION_FILE, //enum for indicating to start sending version file
	ENUM_FT_FILE_LOG_ONLY
};

enum ENUM_FILE_TYPE
{
	ENUM_FT_TYPE_SIGNATURE,
	ENUM_FT_TYPE_SCAN_HISTORY,
	ENUM_FT_TYPE_SCAN_LOG,
	ENUM_FT_TYPE_ACTIVE_MON_LOG,
	ENUM_FT_TYPE_EXCLUDE_DB,
	ENUM_FT_TYPE_CLIENT_UPDATE,
	ENUM_FT_TYPE_VERSION_FILE, //for version file
	ENUM_FT_TYPE_SDLOG_FILE,
	ENUM_FT_TYPE_HIJACK_LOG,
	ENUM_FT_TYPE_DB_FILE, //for transferring database related files.
	ENUM_FT_TYPE_LOG_FOLDER //Log folder
};

// Outer structure for copying file
typedef struct
{
	ENUM_FILE_TRANSFER	enum_File_Transfer;
	ENUM_FILE_TYPE		enum_File_Type;
	BYTE strData[BUF_SIZE_MAX_DATA];		// This buffer ll contain inner struct like FILE_DATA or FILE_INFO
	DWORD dwDataSize;						// Size of file which we hae to send
}FILE_TRANSFER;
const int SIZE_OF_FILE_TRANSFER	= sizeof(FILE_TRANSFER);

// Defferent option settings for corporate
enum ENUM_OPTION_SETTINGS
{
	ENUM_OPT_UNINSTALL_CLIENT = 1,		// Uninstall clients	
	ENUM_OPT_STOP_SCAN,					// Stop scan
	ENUM_OPT_OPEN_REMOVEDB,				// Open Remove DB
	ENUM_OPT_CLOSE_REMOVEDB,			// Close Remove DB
	ENUM_OPT_FAIL_QUARANTINE,			// Fail quarantine process
	ENUM_OPT_SUCCESS_QUARANTINE,		// Successfule quarantine process
	ENUM_OPT_START_REGISTRY_FIX_SCAN,	// 
	ENUM_OPT_SCAN_IN_PROGRESS,			// 
	ENUM_OPT_SCAN_NOT_IN_PROGRESS,		// 
	ENUM_OPT_START_SPECIAL_REMOVAL,		// 
	ENUM_OPT_FINISHED_SPECIAL_REMOVAL,	// 
	ENUM_OPT_IS_CLIENT_INSTALLED,
	ENUM_OPT_CLIENT_INSTALLED_SUCCESSFULLY,
	ENUM_OPT_COPY_SIGNATURE_FILE,
	ENUM_OPT_COPY_LOG,
	
	// Option Tab 
	ENUM_OPT_ENABLE_ACTIVE_PROTECTION,
	ENUM_OPT_DISABLE_ACTIVE_PROTECTION,
	ENUM_OPT_IDENTIFY_UNPROTECTED_NODES,
	ENUM_OPT_LIVE_UPDATE_CLIENT,
	ENUM_OPT_UNINSTALL_CLIENTS,
	ENUM_OPT_GETLATESTLOG,
	ENUM_OPT_VERSIONINFO,
	ENUM_OPT_REQUEST_USERPOLICY_FILE,
	ENUM_OPT_UNINSTALL_COUNT,
	ENUM_OPT_INCR_DB,
	ENUM_OPT_FULL_PATCH,
	ENUM_OPT_CLIENT_INSTALLER,

	ENUM_OPT_READ_REMOVEDB,
	ENUM_OPT_UPDATE_REMOVEDB,
	ENUM_OPT_RESTART_REMOTE_MACHINE,
	ENUM_OPT_GET_CLIENT_VERSION,
	ENUM_OPT_GET_DATABASE_VERSION,
	ENUM_OPT_SCAN_STATUS,
	ENUM_OPT_GET_ALLDB_VERSION,

	ENUM_OPT_PRIORITYPATCH_INSTALLER,
	ENUM_OPT_COMPLEXSPY_INSTALLER,
	ENUM_OPT_VIRUSPATCH_INSTALLER,
	ENUM_OPT_ROOTKIT_PATCH_INSTALLER,
	ENUM_OPT_KEYLOGGER_PATCH_INSTALLER,

	ENUM_OPT_CLEAN_EXCLUDEDB,
	ENUM_OPT_USERPOLICY,
	ENUM_OPT_SHUTDOWN_REMOTE_MACHINE,
	ENUM_OPT_OSVERSION,
	ENUM_OPT_HANDSHAKE,
	ENUM_OPT_UPDATE_IP,
	ENUM_OPT_GET_IP,
	ENUM_OPT_UNINSTALL_FIREWALL,
	ENUM_OPT_CLIENT_COMMAND,
	ENUM_OPT_INSTALL_FIREWALL
};

typedef struct 
{
	ENUM_OPTION_SETTINGS enum_Option_Settings; // setting for above options
	TCHAR sOption[MAX_PATH] ;
	TCHAR szMachineID[MAX_PATH];
	TCHAR szMachineName[MAX_PATH];
}OPTION_SETTINGS;
const int SIZE_OF_OPTION_SETTINGS		= sizeof(OPTION_SETTINGS);

// Activex
typedef struct
{
	char *strActivexName;				// Name of activex
	unsigned int iOperation;			// true for block false for unblock
	unsigned int iActivexNameLen;		// Length of activex which we to block or unblock		
}ACTIVEX_OPTION;	

// BHO option
typedef struct 
{
	char *strBHOName;					// Name of BHO
	bool bBlockBHO;						// true for block and false for unblock
}BHO_OPTION;

// Exclude recover option
typedef struct
{
	char *strWormName;					// Worm name
	bool bExclude;						// true for exclude and false for recover
}EXCLUDE_RECOVER_OPTION;	

// Registry fix option
typedef struct
{
	//char *strWorm;						// Worm path
	ENUM_WORM_STATUS enum_Worm_Status;	// enum for scan log
}REGISTRY_FIX_OPTION;

// LSP option
typedef struct 
{
	char *strLSPEntry;					// LSp entry
}FIX_LSP_OPTION;

//Syatem setings
enum ENUM_SYSTEM_SETTING_OPTION
{
	TAKE_SNAP,							// taking snapshot of registry
	COMAPRE_SNAP						// Compare it with previus one
};

typedef struct
{
	bool bStartupBackup;				// take backup of starup
	bool bRegistryBackup;				// take registry backup
	ENUM_SYSTEM_SETTING_OPTION enum_System_Setting_Option;// enum for selecting system settings
}SYSTEM_SETTINGS;

// Startup entries
enum ENUM_STARTUP_ENTRIES
{
	INSERT_STARTUP_ENTRY,				// Inserting startup entry
	CHANGE_STARTUP_ENTRY,				// change startup entry
	DELETE_STARTUP_ENTRY				// Delete startup entry
};
typedef struct 
{
	ENUM_STARTUP_ENTRIES enum_StratupEntries;// enum for operations like insert,delete,change
	char *strRegKey;					// Registry key
	char *strRegVal;					// Registry value
}STARUP_ENTRIES_OPTION;

// Product information
typedef struct 
{
	bool bAutoMaticLiveUpdate;			// true for automatioc liveupdate and false for manual 
	bool bAutoScan;						// true for start auto scan
	ENUM_WORM_STATUS enum_Worm_Status;  // Log only or quarantine	
}PRODUCT_INIT_SETTINGS;

typedef struct
{
	bool bShowTipsAtStartup;			// true for showing tips at startup;
	bool bShowSysTrayProcKilled;		// Show system tray popup when process get killed
	bool bCleanTempFolder;				// Clean temp folder
	bool bCleanTempIEFiles;				// Clean temporary internet files
}PRODUCT_SYSTEM_SETTINGS;

// Remaining 
// 1. Adding structure for getting BHO entries
typedef struct
{
	char *strBHOID;
	int iBHOIDBufLen;
	char *strPath;
	int iPathBufLen;
	char *strClass;
	int iClassBufLen;
}GET_ALLBHO;
// 2. Adding structure for getting startup entries

enum SOCKET_ERROR_CODE
{
	ENUM_FIREWALL_BLOCKING,
	ENUM_SUCCESS,
	ENUM_SOCKET_OPEN,
	ENUM_INVALID_SOCKET,
	ENUM_SOCKET_ERROR,
	ENUM_VERSION_DIFF,
	ENUM_VERSION_SAME
};

