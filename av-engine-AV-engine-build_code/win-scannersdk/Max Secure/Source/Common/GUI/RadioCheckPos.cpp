#include "pch.h"
#include "RadioCheckPos.h"

CRadioCheckPos::CRadioCheckPos(void)
{
}

CRadioCheckPos::~CRadioCheckPos(void)
{
}

BOOL CRadioCheckPos::UncheckCheckBox(HMODULE hResDLL, CBitmapButtonXP *btnImage)
{
	btnImage->LoadBitmapImage(hResDLL, IDB_BITMAP_NEWCHECKBOX_NORMAL,IDB_BITMAP_NEWCHECKBOX_NORMAL, IDB_BITMAP_CHECK_NORMAL, IDB_BITMAP_NEWCHECKBOX_NORMAL);	
	btnImage->SizeToContent();
	btnImage->Invalidate(1);
	return FALSE;
}

BOOL CRadioCheckPos::CheckCheckBox(HMODULE hResDLL, CBitmapButtonXP *btnImage)
{
	btnImage->LoadBitmapImage(hResDLL, IDB_BITMAP_NEWCHECKBOX_OVER,IDB_BITMAP_NEWCHECKBOX_NORMAL, IDB_BITMAP_CHECK_OVER, IDB_BITMAP_NEWCHECKBOX_OVER);
	btnImage->SizeToContent();
	btnImage->Invalidate(1);
	return TRUE;
}

BOOL CRadioCheckPos::UncheckRadioBox(HMODULE hResDLL, CBitmapButtonXP *btnImage)
{
	btnImage->LoadBitmapImage(hResDLL, IDB_BITMAP_RADIO_UNCHECKED, IDB_BITMAP_RADIO_UNCHECKED,IDB_BITMAP_RADIO_NORMAL,IDB_BITMAP_RADIO_UNCHECKED);	
	btnImage->SizeToContent();
	btnImage->Invalidate(1);
	return FALSE;
}

BOOL CRadioCheckPos::CheckRadioBox(HMODULE hResDLL, CBitmapButtonXP *btnImage)
{
	btnImage->LoadBitmapImage(hResDLL, IDB_BITMAP_RADIO_CHECKED, IDB_BITMAP_RADIO_CHECKED,IDB_BITMAP_RADIO_OVER, IDB_BITMAP_RADIO_CHECKED);	
	btnImage->SizeToContent();
	btnImage->Invalidate(1);
	return TRUE;
}
