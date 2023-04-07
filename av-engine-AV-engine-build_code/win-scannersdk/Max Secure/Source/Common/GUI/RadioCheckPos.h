#pragma once
#include "pch.h"
#include "BitmapButtonXP.h"
class CRadioCheckPos
{
public:
	CRadioCheckPos(void);
	~CRadioCheckPos(void);
	static BOOL UncheckCheckBox(HMODULE m_hResDLL, CBitmapButtonXP *btnImage);
	static BOOL CheckCheckBox(HMODULE m_hResDLL, CBitmapButtonXP *btnImage);
	static BOOL UncheckRadioBox(HMODULE m_hResDLL, CBitmapButtonXP *btnImage);
	static BOOL CheckRadioBox(HMODULE m_hResDLL, CBitmapButtonXP *btnImage);
};
