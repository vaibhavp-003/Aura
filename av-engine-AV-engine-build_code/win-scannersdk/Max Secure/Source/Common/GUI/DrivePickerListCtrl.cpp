/*=============================================================================
   FILE		           : CBitmapButtonXP.h
   ABSTRACT		       : 
   DOCUMENTS	       : Refer The GUI Design.doc, GUI Requirement Document.doc
   AUTHOR		       : 
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE      : 2/24/06
   NOTES		      : Header File for class to create pushbutton controls
                        labeled with bitmapped images instead of text. 
   VERSION HISTORY    : 
				
=============================================================================*/

#include "pch.h"
#include "DrivePickerListCtrl.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


/*-------------------------------------------------------------------------------------
Function       : CDrivePickerListCtrl
In Parameters  : -
Out Parameters : -
Purpose		   : Constructor for class CDrivePickerListCtrl
Author		   :
-------------------------------------------------------------------------------------*/
CDrivePickerListCtrl::CDrivePickerListCtrl()
{
}


/*-------------------------------------------------------------------------------------
Function       : ~CDrivePickerListCtrl
In Parameters  : -
Out Parameters : -
Purpose		   : Destructor for class CDrivePickerListCtrl
Author		   :
-------------------------------------------------------------------------------------*/
CDrivePickerListCtrl::~CDrivePickerListCtrl()
{
	if(NULL != m_ImgList.GetSafeHandle())
	{
		m_ImgList.Detach();
	}
}


BEGIN_MESSAGE_MAP(CDrivePickerListCtrl, CListCtrl)
END_MESSAGE_MAP()


/*-------------------------------------------------------------------------------------
Function       : InitList
In Parameters  : nIconSize: [in] The size of the icons to show in the control. The sizes
supported currently are 16 (for 16x16)and 32 (for 32x32).
nFlags: [in] Flags that determine which type of drives will appear in
the list. See the DDS_DLIL_* constants in the header file.
Out Parameters : void
Purpose		   : Does all the initialization of the list control, sets up the styles,
and fills in the list with drives that match the flags you specify.
Author		   :
-------------------------------------------------------------------------------------*/
void CDrivePickerListCtrl::InitList(int nIconSize, DWORD dwFlags)
{
	// Only 16x16 and 32x32 sizes are supported now.
	ASSERT(16 == nIconSize  ||  32 == nIconSize);
	// Check that only valid flags were passed in.
	ASSERT((dwFlags & DDS_DLIL_ALL_DRIVES) == dwFlags);
	CommonInit(32 == nIconSize, dwFlags);
}

/*-------------------------------------------------------------------------------------
Function       : DrawItem
In Parameters  : dwDrives: [in] Flags indicating which drives should be checked. The
flags are bit 0 for A:, bit 1 for B:, etc.
-or-
szDriveList: [in] String containing the drive letters to select, for
example, "ACD". The string must contain only letters, but
they can be upper- or lower-case.
Out Parameters : void
Purpose		   : Checks the specified drives in the control.
Author		   :
-------------------------------------------------------------------------------------*/
void CDrivePickerListCtrl::SetSelection(const DWORD dwDrives)
{
	int     nIndex;
	int     nMaxIndex = GetItemCount() - 1;
	TCHAR   cNextDrive;
	BOOL    bCheck;

	// Verify that the only bits set are bits 0 thru 25.
	ASSERT((dwDrives &  0x3FFFFFF) == dwDrives);

	for(nIndex = 0; nIndex <= nMaxIndex; nIndex++)
	{
		cNextDrive = static_cast<TCHAR>(GetItemData(nIndex));
		// Internal check - letters are always kept as uppercase.
		ASSERT(_istupper(cNextDrive));
		bCheck =(dwDrives & (1 << (cNextDrive - 'A')));
		SetCheck(nIndex, bCheck);
	}
}

/*-------------------------------------------------------------------------------------
Function       : SetSelection
In Parameters  : LPCTSTR szDrives
Out Parameters : void
Purpose		   :
Author		   :
-------------------------------------------------------------------------------------*/
void CDrivePickerListCtrl::SetSelection(LPCTSTR szDrives)
{
	int     nIndex;
	int     nMaxIndex = GetItemCount() - 1;
	CString sDrives;
	TCHAR   cNextDrive;
	BOOL    bCheck;

#ifdef _DEBUG
	LPCTSTR pchNextDrive = szDrives;
	ASSERT(AfxIsValidString(szDrives));

	// Verify that only letters a thru z are in szDrives.

	for(; '\0' != *pchNextDrive; pchNextDrive++)
	{
		ASSERT(_totupper(*pchNextDrive) >= 'A' &&
			_totupper(*pchNextDrive)<= 'Z');
	}
#endif

	sDrives = szDrives;
	sDrives.MakeUpper();

	for(nIndex = 0; nIndex <= nMaxIndex; nIndex++)
	{
		cNextDrive = static_cast<TCHAR>(GetItemData(nIndex));
		// Internal check - letters are always kept as uppercase.
		ASSERT(_istupper(cNextDrive));
		bCheck =(-1 != sDrives.Find(cNextDrive));
		SetCheck(nIndex, bCheck);
	}
}

/*-------------------------------------------------------------------------------------
Function       : GetNumSelectedDrives
In Parameters  : -
Out Parameters : BYTE - The number of drives that are checked.
Purpose		   : Returns the number of drives whose checkboxes are checked.
Author		   :
-------------------------------------------------------------------------------------*/
BYTE CDrivePickerListCtrl::GetNumSelectedDrives()const
{
	BYTE byNumDrives = 0;
	int  nIndex;
	int  nMaxIndex = GetItemCount() - 1;

	for(nIndex = 0; nIndex <= nMaxIndex; nIndex++)
	{
		if(GetCheck(nIndex))
		{
			byNumDrives++;
		}
	}
	return byNumDrives;
}

/*-------------------------------------------------------------------------------------
Function       : GetSelectedDrives
In Parameters  :   pdwSelectedDrives: [out] Pointer to a DWORD that is set to indicate the
selected drives, where bit 0 corresponds to A:, bit 1
corresponds to B:, etc.
-or-
szSelectedDrives: [out] Pointer to a buffer that is filled with a zero-
terminated string where each characters is a selected
drive, e.g., "ACDIX". This buffer must be at least
27 characters long.
Out Parameters : void
Purpose		   : function to handle event when a
visual aspect of an owner-drawn button has changed.
Returns the drives in the list that are checked.
Author		   :
-------------------------------------------------------------------------------------*/
void CDrivePickerListCtrl::GetSelectedDrives(DWORD* pdwSelectedDrives)const
{
	int nIndex;
	int nMaxIndex = GetItemCount() - 1;
	TCHAR chDrive;

	ASSERT(AfxIsValidAddress(pdwSelectedDrives, sizeof(DWORD)));

	*pdwSelectedDrives = 0;

	for(nIndex = 0; nIndex <= nMaxIndex; nIndex++)
	{
		if(GetCheck(nIndex))
		{
			// Retrieve the drive letter and convert it to the right bit
			// in the DWORD bitmask.

			chDrive = static_cast<TCHAR>(GetItemData(nIndex));

			// Internal check - letters are always kept as uppercase.
			ASSERT(_istupper(chDrive));

			*pdwSelectedDrives |=(1 <<(chDrive - 'A'));
		}
	}
}

/*-------------------------------------------------------------------------------------
Function       : GetSelectedDrives
In Parameters  : szSelectedDrives: [out] Pointer to a buffer that is filled with a zero-
terminated string where each characters is a selected
drive, e.g., "ACDIX". This buffer must be at least
27 characters long.
Out Parameters : void
Purpose		   : function to handle event when a
visual aspect of an owner-drawn button has changed.
Returns the drives in the list that are checked.
Author		   :
-------------------------------------------------------------------------------------*/
void CDrivePickerListCtrl::GetSelectedDrives(LPTSTR szSelectedDrives)const
{
	int   nIndex;
	int   nMaxIndex = GetItemCount() - 1;
	TCHAR szDrive[2] ={0, 0 };

	// Need at least a 27-char buffer to hold A-Z and the terminating zero.
	int iBuffLen = 27 * sizeof(TCHAR);
	ASSERT(AfxIsValidAddress(szSelectedDrives, iBuffLen));

	*szSelectedDrives = 0;

	for(nIndex = 0; nIndex <= nMaxIndex; nIndex++)
	{
		if(GetCheck(nIndex))
		{
			*szDrive = static_cast<TCHAR>(GetItemData(nIndex));

			wcscat_s(szSelectedDrives, iBuffLen, szDrive);
		}
	}
}

/*-------------------------------------------------------------------------------------
Function       : CommonInit
In Parameters  : bLargeIcons: [in] Pass TRUE to put large icons in the control, or FALSE
to use small icons.
nFlags: [in] Same flags as InitList()takes.
Out Parameters : void
Purpose		   :  Really does all the initialization of the list control, sets up the
styles, and fills in the list with drives that match the flags specified
in the call to InitList().
Author		   :
-------------------------------------------------------------------------------------*/
void CDrivePickerListCtrl::CommonInit(BOOL bLargeIcons, DWORD dwFlags)
{
	DWORD dwRemoveStyles = LVS_TYPEMASK | LVS_SORTASCENDING | LVS_SORTDESCENDING |
		LVS_OWNERDRAWFIXED | LVS_SHOWSELALWAYS;
	DWORD dwNewStyles = LVS_REPORT | LVS_NOCOLUMNHEADER | LVS_SHAREIMAGELISTS |
		LVS_SINGLESEL;

	DWORD dwRemoveExStyles = 0;
	DWORD dwNewExStyles = LVS_EX_CHECKBOXES;

	ASSERT(0  == (GetStyle()& LVS_OWNERDATA));

	ModifyStyle(dwRemoveStyles, dwNewStyles);
	ListView_SetExtendedListViewStyleEx(GetSafeHwnd(),
		dwRemoveExStyles | dwNewExStyles,
		dwNewExStyles);
	DeleteAllItems();

	LVCOLUMN rCol ={LVCF_WIDTH };

	if(!GetColumn(0, &rCol))
	{
		InsertColumn(0, _T(""));
	}


	// Get the handle of the system image list - which list we retrieve
	// (large or small icons)is controlled by the bLargeIcons parameter.

	SHFILEINFO sfi;
	DWORD_PTR	dwRet;
	HIMAGELIST hImgList;
	UINT       uFlags = SHGFI_USEFILEATTRIBUTES | SHGFI_SYSICONINDEX;

	uFlags |=(bLargeIcons ? SHGFI_LARGEICON : SHGFI_SMALLICON);

	BOOL bVal = FALSE;
	try
	{
		dwRet = SHGetFileInfo(_T("buffy.com"), FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(SHFILEINFO), uFlags);
		bVal = TRUE;
	}
	catch(...)
	{
	}

	DestroyIcon(sfi.hIcon);
	hImgList = reinterpret_cast<HIMAGELIST>(dwRet);
	ASSERT(NULL != hImgList);

	if(NULL != m_ImgList.GetSafeHandle())
		m_ImgList.Detach();

	VERIFY(m_ImgList.Attach(hImgList));

	SetImageList(&m_ImgList, LVSIL_SMALL);
	TCHAR szDriveRoot[] = _T("x:\\");
	TCHAR cDrive;
	DWORD dwDrivesOnSystem = GetLogicalDrives();
	int   nIndex = 0;
	UINT  uDriveType;

	// Sanity check - if this assert fires, how the heck did you boot? :)
	ASSERT(0 != dwDrivesOnSystem);


	uFlags = SHGFI_SYSICONINDEX | SHGFI_DISPLAYNAME | SHGFI_ICON;
	uFlags |=(bLargeIcons ? SHGFI_LARGEICON : SHGFI_SMALLICON);

	for(cDrive = 'A'; cDrive <= 'Z'; cDrive++, dwDrivesOnSystem >>= 1)
	{
		if(!(dwDrivesOnSystem & 1))
			continue;

		// Get the type for the next drive, and check dwFlags to determine
		// if we should show it in the list.

		szDriveRoot[0] = cDrive;

		uDriveType = GetDriveType(szDriveRoot);

		switch(uDriveType)
		{
		case DRIVE_NO_ROOT_DIR:
		case DRIVE_UNKNOWN:
			// Skip disconnected network drives and drives that Windows
			// can't figure out.
			continue;
			break;

		case DRIVE_REMOVABLE:
			if(!(dwFlags & DDS_DLIL_REMOVABLES))
				continue;
			break;

		case DRIVE_FIXED:
			if(!(dwFlags & DDS_DLIL_HARDDRIVES))
				continue;
			break;

		case DRIVE_REMOTE:
			if(!(dwFlags & DDS_DLIL_NETDRIVES))
				continue;
			break;

		case DRIVE_CDROM:
			if(!(dwFlags & DDS_DLIL_CDROMS))
				continue;
			break;

		case DRIVE_RAMDISK:
			if(!(dwFlags & DDS_DLIL_RAMDRIVES))
				continue;
			break;

			DEFAULT_UNREACHABLE;
		}

		if(bVal)
		{
			SHGetFileInfo(szDriveRoot, 0, &sfi, sizeof(SHFILEINFO),uFlags);
			InsertItem(nIndex, sfi.szDisplayName, sfi.iIcon);
			DestroyIcon(sfi.hIcon);
		}
		else
			InsertItem(nIndex, szDriveRoot);

		SetItemData(nIndex, cDrive);
		nIndex++;
	}   // end for

	SetColumnWidth(0, LVSCW_AUTOSIZE_USEHEADER);
}
