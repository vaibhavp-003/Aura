#pragma once
#include "pch.h"
#include "S2S.h"
#include "SDSystemInfo.h"

typedef struct _ExludeExtensions
{
	wchar_t extension[20];
} ExludeExtensions;

class CExtensionList
{
public :
	CExtensionList();
	~CExtensionList();

public:
	CS2S	m_objDBAppExtList;
	void	OnClickedApply(int iListSize, wchar_t** csExtensionList);

	int		GetExtensionCnt();

	int		FillExtensionArray(ExludeExtensions* pExtensionArray, int size);
};
