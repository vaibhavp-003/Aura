/*======================================================================================
   FILE			: tbtremfc.cpp 
   ABSTRACT		: implementation file for derived mfc oriented classes
   DOCUMENTS	: Reffer The Design Folder (FastMap Design.Doc)
   AUTHOR		: Dipali Pawar
   COMPANY		: Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE: 1/sep/2007
   NOTES		:
   VERSION HISTORY	:
					Version: 19-jan-08
					Resourec:Darshan
					Description: Added unicode and X64 support
======================================================================================*/

#include "tbtremfc.h"                  

// MFC Derived tree class: CtStringToString
IMPLEMENT_SERIAL(CtStringToString, CObject, 0)

CtStringToString::~CtStringToString()
{
    RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: Serialize
	In Parameters	: CArchive& ar - archive
	Out Parameters	: -
	Purpose			: Serialize function
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void CtStringToString::Serialize(CArchive& ar)
{
	CObject::Serialize( ar );
    m_bufSize = -1;                             // inticates CArchive 
    if (ar.IsStoring())
    {
        ar << GetCount();
        storeTree((void*)&ar);
    }
    else
    {
        RemoveAll();
        long imbalance = SetAutoBalance(0);     // turn off autobalance
        long count;
        CString key,data;
        ar >> count;
        while (count)
        {
            ar >> key;
            ar >> data;
            Set(key,data);
            count--;
        }
        SetAutoBalance(imbalance);              // resume autobalance
    }
}

/*-------------------------------------------------------------------------------------
	Function		: onStore
	In Parameters	: void* where - destination
					  POSITION node - node
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Store one item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int CtStringToString::onStore(void* where, POSITION node)
{
    int ok = 1;
    if (m_bufSize == -1)
    {
        CArchive& ar = (CArchive&)(*(CArchive*)where);
        ar << (CString) GetKey(node);
        ar << (CString) GetData(node);
    }
    else
        ok = tStringToString::onStore(where, node);
    return ok;
}


// MFC Derived tree class: CtStringToULong
IMPLEMENT_SERIAL(CtStringToULong, CObject, 0)

CtStringToULong::~CtStringToULong()
{
    RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: Serialize
	In Parameters	: CArchive& ar - archive
	Out Parameters	: -
	Purpose			: Serialize function
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void CtStringToULong::Serialize(CArchive& ar)
{
    m_bufSize = -1;                             // inticates CArchive 
    if (ar.IsStoring())
    {
        ar << GetCount();
        storeTree((void*)&ar);
    }
    else
    {
        RemoveAll();
        long imbalance = SetAutoBalance(0);     // turn off autobalance
        long count;
        CString key;
        unsigned long data;
        ar >> count;
        while (count)
        {
            ar >> key;
            ar >> data;
            Set(key,data);
            count--;
        }
        SetAutoBalance(imbalance);              // resume autobalance
    }
}

/*-------------------------------------------------------------------------------------
	Function		: onStore
	In Parameters	: void* where - destination
					  POSITION node - node
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Store one item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int CtStringToULong::onStore(void* where, POSITION node)
{
    int ok = 1;
    if (m_bufSize == -1)
    {
        CArchive& ar = (CArchive&)(*(CArchive*)where);
        ar << (CString)GetKey(node);
        ar << GetData(node);
    }
    else
        ok = tStringToULong::onStore(where, node);
    return ok;
}


// MFC Derived tree class: CtStringToCObject
IMPLEMENT_SERIAL(CtStringToCObject, CObject, 0)

CtStringToCObject::~CtStringToCObject()
{
    RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: onDeleteData
	In Parameters	: void*& dataPtr - data
	Out Parameters	: -
	Purpose			: delete data
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void CtStringToCObject::onDeleteData(void*& dataPtr)
{
    delete (CObject*)dataPtr;
	dataPtr = NULL;
}

/*-------------------------------------------------------------------------------------
	Function		: onSetData
	In Parameters	: void*& dataPtr - destibation data
					  void* data  source data
	Out Parameters	: int - success ful or not
	Purpose			: Set data
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int CtStringToCObject::onSetData(void*& dataPtr, void* data)
{
    dataPtr = data;
    return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: Serialize
	In Parameters	: CArchive& ar - archive
	Out Parameters	: -
	Purpose			: Serialize function
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void CtStringToCObject::Serialize(CArchive& ar)
{
    m_bufSize = -1;                             // inticates CArchive 
    if (ar.IsStoring())
    {
        ar << GetCount();
        storeTree((void*)&ar);
    }
    else
    {
        RemoveAll();
        long imbalance = SetAutoBalance(0);     // turn off autobalance
        long count;
        CString key;
        CObject* data;
        ar >> count;
        while (count)
        {
            ar >> key;
            ar >> data;
            Set(key,data);
            count--;
        }
        SetAutoBalance(imbalance);              // resume autobalance
    }
}

/*-------------------------------------------------------------------------------------
	Function		: onStore
	In Parameters	: void* where - destination
					  POSITION node - node
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Store one item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int CtStringToCObject::onStore(void* where, POSITION node)
{
    int ok = 1;
    if (m_bufSize == -1)
    {
        CArchive& ar = (CArchive&)(*(CArchive*)where);
        ar << (CString)GetKey(node);
        ar << GetData(node);
    }
    else
        ok = 0;
    return ok;
}


// MFC Derived tree class: CtULongToString
IMPLEMENT_SERIAL(CtULongToString, CObject, 0)

CtULongToString::~CtULongToString()
{
    RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: Serialize
	In Parameters	: CArchive& ar - archive
	Out Parameters	: -
	Purpose			: Serialize function
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void CtULongToString::Serialize(CArchive& ar)
{
    m_bufSize = -1;                             // inticates CArchive 
    if (ar.IsStoring())
    {
        ar << GetCount();
        storeTree((void*)&ar);
    }
    else
    {
        RemoveAll();
        long imbalance = SetAutoBalance(0);     // turn off autobalance
        long count;
        unsigned long key;
        CString data;
        ar >> count;
        while (count)
        {
            ar >> key;
            ar >> data;
            Set(key,data);
            count--;
        }
        SetAutoBalance(imbalance);              // resume autobalance
    }
}

/*-------------------------------------------------------------------------------------
	Function		: onStore
	In Parameters	: void* where - destination
					  POSITION node - node
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Store one item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int CtULongToString::onStore(void* where, POSITION node)
{
    int ok = 1;
    if (m_bufSize == -1)
    {
        CArchive& ar = (CArchive&)(*(CArchive*)where);
        ar << GetKey(node);
        ar << (CString)GetData(node);
    }
    else
        ok = tULongToString::onStore(where, node);
    return ok;
}


// MFC Derived tree class: CtULongToULong
IMPLEMENT_SERIAL(CtULongToULong, CObject, 0)

CtULongToULong::~CtULongToULong()
{
    RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: Serialize
	In Parameters	: CArchive& ar - archive
	Out Parameters	: -
	Purpose			: Serialize function
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void CtULongToULong::Serialize(CArchive& ar)
{
    m_bufSize = -1;                             // inticates CArchive 
    if (ar.IsStoring())
    {
        ar << GetCount();
        storeTree((void*)&ar);
    }
    else
    {
        RemoveAll();
        long imbalance = SetAutoBalance(0);     // turn off autobalance
        long count;
        unsigned long key;
        unsigned long data;
        ar >> count;
        while (count)
        {
            ar >> key;
            ar >> data;
            Set(key,data);
            count--;
        }
        SetAutoBalance(imbalance);              // resume autobalance
    }
}

/*-------------------------------------------------------------------------------------
	Function		: onStore
	In Parameters	: void* where - destination
					  POSITION node - node
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Store one item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int CtULongToULong::onStore(void* where, POSITION node)
{
    int ok = 1;
    if (m_bufSize == -1)
    {
        CArchive& ar = (CArchive&)(*(CArchive*)where);
        ar << GetKey(node);
        ar << GetData(node);
    }
    else
        ok = tULongToULong::onStore(where, node);
    return ok;
}


// MFC Derived tree class: CtULongToCObject
IMPLEMENT_SERIAL(CtULongToCObject, CObject, 0)

CtULongToCObject::~CtULongToCObject()
{
    RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: onDeleteData
	In Parameters	: void*& dataPtr - data
	Out Parameters	: -
	Purpose			: delete data
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void CtULongToCObject::onDeleteData(void*& dataPtr)
{
    delete (CObject*)dataPtr;
}

/*-------------------------------------------------------------------------------------
	Function		: onSetData
	In Parameters	: void*& dataPtr - destibation data
					  void* data  source data
	Out Parameters	: -
	Purpose			: Set data
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int CtULongToCObject::onSetData(void*& dataPtr, void* data)
{
    dataPtr = data;
    return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: Serialize
	In Parameters	: CArchive& ar - archive
	Out Parameters	: -
	Purpose			: Serialize function
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void CtULongToCObject::Serialize(CArchive& ar)
{
    m_bufSize = -1;                             // inticates CArchive 
    if (ar.IsStoring())
    {
        ar << GetCount();
        storeTree((void*)&ar);
    }
    else
    {
        RemoveAll();
        long imbalance = SetAutoBalance(0);     // turn off autobalance
        long count;
        unsigned long key;
        CObject* data;
        ar >> count;
        while (count)
        {
            ar >> key;
            ar >> data;
            Set(key,data);
            count--;
        }
        SetAutoBalance(imbalance);              // resume autobalance
    }
}

/*-------------------------------------------------------------------------------------
	Function		: onStore
	In Parameters	: void* where - destination
					  POSITION node - node
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Store one item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int CtULongToCObject::onStore(void* where, POSITION node)
{
    int ok = 1;
    if (m_bufSize == -1)
    {
        CArchive& ar = (CArchive&)(*(CArchive*)where);
        ar << GetKey(node);
        ar << GetData(node);
    }
    else
        ok = 0;
    return ok;
}


// MFC Derived tree class: CtLongToString
IMPLEMENT_SERIAL(CtLongToString, CObject, 0)

CtLongToString::~CtLongToString()
{
    RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: Serialize
	In Parameters	: CArchive& ar - archive
	Out Parameters	: -
	Purpose			: Serialize function
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void CtLongToString::Serialize(CArchive& ar)
{
    m_bufSize = -1;                             // inticates CArchive 
    if (ar.IsStoring())
    {
        ar << GetCount();
        storeTree((void*)&ar);
    }
    else
    {
        RemoveAll();
        long imbalance = SetAutoBalance(0);     // turn off autobalance
        long count;
        long key;
        CString data;
        ar >> count;
        while (count)
        {
            ar >> key;
            ar >> data;
            Set(key,data);
            count--;
        }
        SetAutoBalance(imbalance);              // resume autobalance
    }
}

/*-------------------------------------------------------------------------------------
	Function		: onStore
	In Parameters	: void* where - destination
					  POSITION node - node
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Store one item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int CtLongToString::onStore(void* where, POSITION node)
{
    int ok = 1;
    if (m_bufSize == -1)
    {
        CArchive& ar = (CArchive&)(*(CArchive*)where);
        ar << GetKey(node);
        ar << (CString)GetData(node);
    }
    else
        ok = tLongToString::onStore(where, node);
    return ok;
}


// MFC Derived tree class: CtLongToULong
IMPLEMENT_SERIAL(CtLongToULong, CObject, 0)

CtLongToULong::~CtLongToULong()
{
    RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: Serialize
	In Parameters	: CArchive& ar - archive
	Out Parameters	: -
	Purpose			: Serialize function
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void CtLongToULong::Serialize(CArchive& ar)
{
    m_bufSize = -1;                             // inticates CArchive 
    if (ar.IsStoring())
    {
        ar << GetCount();
        storeTree((void*)&ar);
    }
    else
    {
        RemoveAll();
        long imbalance = SetAutoBalance(0);     // turn off autobalance
        long count;
        long key;
        unsigned long data;
        ar >> count;
        while (count)
        {
            ar >> key;
            ar >> data;
            Set(key,data);
            count--;
        }
        SetAutoBalance(imbalance);              // resume autobalance
    }
}

/*-------------------------------------------------------------------------------------
	Function		: onStore
	In Parameters	: void* where - destination
					  POSITION node - node
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Store one item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int CtLongToULong::onStore(void* where, POSITION node)
{
    int ok = 1;
    if (m_bufSize == -1)
    {
        CArchive& ar = (CArchive&)(*(CArchive*)where);
        ar << GetKey(node);
        ar << GetData(node);
    }
    else
        ok = tLongToULong::onStore(where, node);
    return ok;
}


// MFC Derived tree class: CtLongToCObject
IMPLEMENT_SERIAL(CtLongToCObject, CObject, 0)

CtLongToCObject::~CtLongToCObject()
{
    RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: onDeleteData
	In Parameters	: void*& dataPtr - data
	Out Parameters	: -
	Purpose			: delete data
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void CtLongToCObject::onDeleteData(void*& dataPtr)
{
    delete (CObject*)dataPtr;
}

/*-------------------------------------------------------------------------------------
	Function		: onSetData
	In Parameters	: void*& dataPtr - destibation data
					  void* data  source data
	Out Parameters	: -
	Purpose			: Set data
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int CtLongToCObject::onSetData(void*& dataPtr, void* data)
{
    dataPtr = data;
    return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: Serialize
	In Parameters	: CArchive& ar - archive
	Out Parameters	: -
	Purpose			: Serialize function
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void CtLongToCObject::Serialize(CArchive& ar)
{
    m_bufSize = -1;                             // inticates CArchive 
    if (ar.IsStoring())
    {
        ar << GetCount();
        storeTree((void*)&ar);
    }
    else
    {
        RemoveAll();
        long imbalance = SetAutoBalance(0);     // turn off autobalance
        long count;
        long key;
        CObject* data;
        ar >> count;
        while (count)
        {
            ar >> key;
            ar >> data;
            Set(key,data);
            count--;
        }
        SetAutoBalance(imbalance);              // resume autobalance
    }
}

/*-------------------------------------------------------------------------------------
	Function		: onStore
	In Parameters	: void* where - destination
					  POSITION node - node
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Store one item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int CtLongToCObject::onStore(void* where, POSITION node)
{
    int ok = 1;
    if (m_bufSize == -1)
    {
        CArchive& ar = (CArchive&)(*(CArchive*)where);
        ar << GetKey(node);
        ar << GetData(node);
    }
    else
        ok = 0;
    return ok;
}
