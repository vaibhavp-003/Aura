/*======================================================================================
   FILE			: tbtreed.cpp 
   ABSTRACT		: derived binary tree classes for non mfc application
   DOCUMENTS	: Refer The Design Folder (FastMap Design.Doc)
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
   REVISION HISTORY :
			
======================================================================================*/

#include "tbtreed.h"                    // class header

// Derived tree class: tStringToString
/*-------------------------------------------------------------------------------------
	Function		: ~tStringToString
	In Parameters	: -
	Out Parameters	: -
	Purpose			: destructor
	Author			: Dipali
--------------------------------------------------------------------------------------*/
tStringToString::~tStringToString()
{
    RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: onDeleteKey
	In Parameters	: void*& keyPtr - key pointer
	Out Parameters	: -
	Purpose			: delete key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void tStringToString::onDeleteKey(void*& keyPtr)
{
    free(keyPtr);
}

/*-------------------------------------------------------------------------------------
	Function		: onDeleteData
	In Parameters	: void*& dataPtr - data pointer
	Out Parameters	: -
	Purpose			: delete data
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void tStringToString::onDeleteData(void*& dataPtr)
{
    free(dataPtr);
}

/*-------------------------------------------------------------------------------------
	Function		: onSetKey
	In Parameters	: void*& keyPtr - key pointer
					  void* key - source key
	Out Parameters	: int - 1 successful
	Purpose			: Set Key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tStringToString::onSetKey(void*& keyPtr, void* key)
{
    keyPtr = _wcsdup((const TCHAR*)key);
    return keyPtr ? 1 : 0;
}

/*-------------------------------------------------------------------------------------
	Function		: onSetData
	In Parameters	: void*& dataPtr - data pointer
					  void* data - source data
	Out Parameters	: int - 1 successful
	Purpose			: Set data
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tStringToString::onSetData(void*& dataPtr, void* data)
{
    dataPtr = _wcsdup((const TCHAR*)data);
    return dataPtr ? 1 : 0;
}

/*-------------------------------------------------------------------------------------
	Function		: onCompareKeys
	In Parameters	: void* key1 - first key
					  void* key2 - second key
	Out Parameters	: relativeKeyValue - relative key
	Purpose			: compare keys
	Author			: Dipali
--------------------------------------------------------------------------------------*/
tStringToString::relativeKeyValue tStringToString::onCompareKeys(void* key1, void* key2)
{
    return (relativeKeyValue)wcscmp((const TCHAR*)key1, (const TCHAR*)key2);
}

/*-------------------------------------------------------------------------------------
	Function		: onGetKeyName
	In Parameters	: void* keyPtr - key pointer
	Out Parameters	: const TCHAR* - key name
	Purpose			: Get key name
	Author			: Dipali
--------------------------------------------------------------------------------------*/
const TCHAR* tStringToString::onGetKeyName(void* keyPtr)
{
    return (const TCHAR*)keyPtr;
}

/*-------------------------------------------------------------------------------------
	Function		: onStore
	In Parameters	: void* where - destination
					  POSITION node - node
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Store one item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tStringToString::onStore(void* where, POSITION node)
{
    const TCHAR* string = (const TCHAR*)getKey(node);
    long len = long(wcslen(string) + 1);
    m_bufSize = __max(m_bufSize, len);
    int ok = streamWrite((NQ wostream*)where, (void*)string, len);
    if (ok)
    {
        string = (const TCHAR*)getData(node);
        len = long(wcslen(string) + 1);
        m_bufSize = __max(m_bufSize, len);
        ok = streamWrite((NQ wostream*)where, (void*)string, len);
    }
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: onLoad
	In Parameters	: void* where - source
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Load the next item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tStringToString::onLoad(void* where)
{
    long kLen, dLen;
    int ok = streamRead((NQ wistream*)where, (TCHAR*)m_keyBuf, m_bufSize, kLen);
    if (ok)
    {
        ok = streamRead((NQ wistream*)where, (TCHAR*)m_dataBuf, m_bufSize, dLen);
        if (ok)
            ok = Set((TCHAR*)m_keyBuf, (TCHAR*)m_dataBuf);
    }
    return ok;
}


// Derived tree class: tStringToULong

/*-------------------------------------------------------------------------------------
	Function		: ~tStringToULong
	In Parameters	: -
	Out Parameters	: -
	Purpose			: destructor.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
tStringToULong::~tStringToULong()
{
    RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: onDeleteKey
	In Parameters	: void*& keyPtr - key pointer
	Out Parameters	: -
	Purpose			: delete key.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void tStringToULong::onDeleteKey(void*& keyPtr)
{
    free(keyPtr);
}

/*-------------------------------------------------------------------------------------
	Function		: onDeleteData
	In Parameters	: void*& dataPtr - data pointer
	Out Parameters	: -
	Purpose			: delete data.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void tStringToULong::onDeleteData(void*& dataPtr)
{
}

/*-------------------------------------------------------------------------------------
	Function		: onSetKey
	In Parameters	: void*& keyPtr - destination key pointer
					  void* key - source key
	Out Parameters	: int - 1 successful
	Purpose			: set key.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tStringToULong::onSetKey(void*& keyPtr, void* key)
{
    keyPtr = _wcsdup((const TCHAR*)key);
    return keyPtr ? 1 : 0;
}

/*-------------------------------------------------------------------------------------
	Function		: onSetData
	In Parameters	: void*& dataPtr - data pointer
					  void* data - source data
	Out Parameters	: int - 1 successful
	Purpose			: Set data
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tStringToULong::onSetData(void*& dataPtr, void* data)
{
    dataPtr = data;
    return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: onCompareKeys
	In Parameters	: void* key1 - first key
					  void* key2 - second key
	Out Parameters	: relativeKeyValue - relative key
	Purpose			: compare keys
	Author			: Dipali
--------------------------------------------------------------------------------------*/
tStringToULong::relativeKeyValue tStringToULong::onCompareKeys(void* key1, void* key2)
{
    return (relativeKeyValue)wcscmp((const TCHAR*)key1, (const TCHAR*)key2);
}

/*-------------------------------------------------------------------------------------
	Function		: onGetKeyName
	In Parameters	: void* keyPtr - key pointer
	Out Parameters	: const TCHAR* - key name
	Purpose			: Get key name
	Author			: Dipali
--------------------------------------------------------------------------------------*/
const TCHAR* tStringToULong::onGetKeyName(void* keyPtr)
{
    return (const TCHAR*)keyPtr;
}

/*-------------------------------------------------------------------------------------
	Function		: onStore
	In Parameters	: void* where - destination
					  POSITION node - node
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Store one item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tStringToULong::onStore(void* where, POSITION node)
{
    const TCHAR* string = (const TCHAR*)getKey(node);
    long len = long(wcslen(string) + 1);
    m_bufSize = __max(m_bufSize, len);
    int ok = streamWrite((NQ wostream*)where, (void*)string, len);
    if (ok)
    {
        unsigned long val = (unsigned long)getData(node);
        len = sizeof(val);
        m_bufSize = __max(m_bufSize, len);
        ok = streamWrite((NQ wostream*)where, (void*)&val, len);
    }
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: onLoad
	In Parameters	: void* where - source
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Load the next item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tStringToULong::onLoad(void* where)
{
    long kLen;
    unsigned long data;
    int ok = streamRead((NQ wistream*)where, (TCHAR*)m_keyBuf, m_bufSize, kLen);
    if (ok)
    {
        ok = streamRead((NQ wistream*)where, (TCHAR*)&data, sizeof(data));
        if (ok)
            ok = Set((const TCHAR*)m_keyBuf, data);
    }
    return ok;
}


// Derived tree class: tULongToString
/*-------------------------------------------------------------------------------------
	Function		: ~tULongToString
	In Parameters	: -
	Out Parameters	: -
	Purpose			: destructor.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
tULongToString::~tULongToString()
{
    RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: onDeleteKey
	In Parameters	: void*& keyPtr - key pointer
	Out Parameters	: -
	Purpose			: delete key.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void tULongToString::onDeleteKey(void*& keyPtr)
{
}

/*-------------------------------------------------------------------------------------
	Function		: onDeleteData
	In Parameters	: void*& dataPtr - data pointer
	Out Parameters	: -
	Purpose			: delete data.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void tULongToString::onDeleteData(void*& dataPtr)
{
    free(dataPtr);
}

/*-------------------------------------------------------------------------------------
	Function		: onSetKey
	In Parameters	: void*& keyPtr - destination key pointer
					  void* key - source key
	Out Parameters	: int - 1 successful
	Purpose			: set key.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tULongToString::onSetKey(void*& keyPtr, void* key)
{
    keyPtr = key;
    return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: onSetData
	In Parameters	: void*& dataPtr - data pointer
					  void* data - source data
	Out Parameters	: int - 1 successful
	Purpose			: Set data
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tULongToString::onSetData(void*& dataPtr, void* data)
{
    dataPtr = _wcsdup((const TCHAR*)data);
    return dataPtr ? 1 : 0;
}

/*-------------------------------------------------------------------------------------
	Function		: onCompareKeys
	In Parameters	: void* key1 - first key
					  void* key2 - second key
	Out Parameters	: relativeKeyValue - relative key
	Purpose			: compare keys
	Author			: Dipali
--------------------------------------------------------------------------------------*/
tULongToString::relativeKeyValue tULongToString::onCompareKeys(void* key1, void* key2)
{
    if ((unsigned long)key1 < (unsigned long)key2)
        return less;
    if ((unsigned long)key1 == (unsigned long)key2)
        return equal;
    return greater;
}

/*-------------------------------------------------------------------------------------
	Function		: onGetKeyName
	In Parameters	: void* keyPtr - key pointer
	Out Parameters	: const TCHAR* - key name
	Purpose			: Get key name
	Author			: Dipali
--------------------------------------------------------------------------------------*/
static TCHAR keyName_tULongToString[30];
const TCHAR* tULongToString::onGetKeyName(void* keyPtr)
{
    swprintf(keyName_tULongToString, _countof(keyName_tULongToString),_T("%lu"), (unsigned long)keyPtr);
    return (const TCHAR*)keyName_tULongToString;
}

/*-------------------------------------------------------------------------------------
	Function		: onStore
	In Parameters	: void* where - destination
					  POSITION node - node
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Store one item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tULongToString::onStore(void* where, POSITION node)
{
    unsigned long key = (unsigned long)getKey(node);
    int ok = streamWrite((NQ wostream*)where, (void*)&key, sizeof(key));
    if (ok)
    {
        const TCHAR* string = (const TCHAR*)getData(node);
        long len = long(wcslen(string) + 1);
        m_bufSize = __max(m_bufSize, len);
        ok = streamWrite((NQ wostream*)where, (void*)string, len);
    }
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: onLoad
	In Parameters	: void* where - source
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Load the next item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tULongToString::onLoad(void* where)
{
    unsigned long key;
    long dLen;
    int ok = streamRead((NQ wistream*)where, (TCHAR*)&key, sizeof(key));
    if (ok)
    {
        ok = streamRead((NQ wistream*)where, (TCHAR*)m_dataBuf, m_bufSize, dLen);
        if (ok)
            ok = Set(key, (const TCHAR*)m_dataBuf);
    }
    return ok;
}


// Derived tree class: tULongToULong

/*-------------------------------------------------------------------------------------
	Function		: ~tULongToULong
	In Parameters	: -
	Out Parameters	: -
	Purpose			: destructor.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
tULongToULong::~tULongToULong()
{
    RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: onDeleteKey
	In Parameters	: void*& keyPtr - key pointer
	Out Parameters	: -
	Purpose			: delete key. 
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void tULongToULong::onDeleteKey(void*& keyPtr)
{
}

/*-------------------------------------------------------------------------------------
	Function		: onDeleteData
	In Parameters	: void*& dataPtr - data pointer
	Out Parameters	: -
	Purpose			: delete data.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void tULongToULong::onDeleteData(void*& dataPtr)
{
}

/*-------------------------------------------------------------------------------------
	Function		: onSetKey
	In Parameters	: void*& keyPtr - destination key pointer
					  void* key - source key
	Out Parameters	: int - 1 successful
	Purpose			: set key.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tULongToULong::onSetKey(void*& keyPtr, void* key)
{
    keyPtr = key;
    return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: onSetData
	In Parameters	: void*& dataPtr - data pointer
					  void* data - source data
	Out Parameters	: int - 1 successful
	Purpose			: Set data
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tULongToULong::onSetData(void*& dataPtr, void* data)
{
    dataPtr = data;
    return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: onCompareKeys
	In Parameters	: void* key1 - first key
					  void* key2 - second key
	Out Parameters	: relativeKeyValue - relative key
	Purpose			: compare keys
	Author			: Dipali
--------------------------------------------------------------------------------------*/
tULongToULong::relativeKeyValue tULongToULong::onCompareKeys(void* key1, void* key2)
{
    if ((unsigned long)key1 < (unsigned long)key2)
        return less;
    if ((unsigned long)key1 == (unsigned long)key2)
        return equal;
    return greater;
}

/*-------------------------------------------------------------------------------------
	Function		: onGetKeyName
	In Parameters	: void* keyPtr - key pointer
	Out Parameters	: const TCHAR* - key name
	Purpose			: Get key name
	Author			: Dipali
--------------------------------------------------------------------------------------*/
static TCHAR keyName_tULongToULong[30];
const TCHAR* tULongToULong::onGetKeyName(void* keyPtr)
{
    swprintf(keyName_tULongToULong, _countof(keyName_tULongToULong),_T("%lu"), (unsigned long)keyPtr);
    return (const TCHAR*)keyName_tULongToULong;
}

/*-------------------------------------------------------------------------------------
	Function		: onStore
	In Parameters	: void* where - destination
					  POSITION node - node
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Store one item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tULongToULong::onStore(void* where, POSITION node)
{
    unsigned long key = (unsigned long)getKey(node);
    int ok = streamWrite((NQ wostream*)where, (void*)&key, sizeof(key));
    if (ok)
    {
        unsigned long data = (unsigned long)getData(node);
        ok = streamWrite((NQ wostream*)where, (void*)&data, sizeof(data));
    }
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: onLoad
	In Parameters	: void* where - source
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Load the next item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tULongToULong::onLoad(void* where)
{
    unsigned long key, data;
    int ok = streamRead((NQ wistream*)where, (TCHAR*)&key, sizeof(key));
    if (ok)
    {
        ok = streamRead((NQ wistream*)where, (TCHAR*)&data, sizeof(data));
        if (ok)
            ok = Set(key, data);
    }
    return ok;
}


// Derived tree class: tLongToString

/*-------------------------------------------------------------------------------------
	Function		: ~tLongToString
	In Parameters	: -
	Out Parameters	: -
	Purpose			: destructor.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
tLongToString::~tLongToString()
{
    RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: onDeleteKey
	In Parameters	: void*& keyPtr - key pointer
	Out Parameters	: -
	Purpose			: delete key.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void tLongToString::onDeleteKey(void*& keyPtr)
{
}

/*-------------------------------------------------------------------------------------
	Function		: onDeleteData
	In Parameters	: void*& dataPtr - data pointer
	Out Parameters	: -
	Purpose			: delete data.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void tLongToString::onDeleteData(void*& dataPtr)
{
    free(dataPtr);
}

/*-------------------------------------------------------------------------------------
	Function		: onSetKey
	In Parameters	: void*& keyPtr - destination key pointer
					  void* key - source key
	Out Parameters	: int - 1 successful
	Purpose			: set key.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tLongToString::onSetKey(void*& keyPtr, void* key)
{
    keyPtr = key;
    return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: onSetData
	In Parameters	: void*& dataPtr - data pointer
					  void* data - source data
	Out Parameters	: int - 1 successful
	Purpose			: Set data
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tLongToString::onSetData(void*& dataPtr, void* data)
{
    dataPtr = _wcsdup((const TCHAR*)data);
    return dataPtr ? 1 : 0;
}

/*-------------------------------------------------------------------------------------
	Function		: onCompareKeys
	In Parameters	: void* key1 - first key
					  void* key2 - second key
	Out Parameters	: relativeKeyValue - relative key
	Purpose			: compare keys
	Author			: Dipali
--------------------------------------------------------------------------------------*/
tLongToString::relativeKeyValue tLongToString::onCompareKeys(void* key1, void* key2)
{
    if ((long)key1 < (long)key2)
        return less;
    if ((long)key1 == (long)key2)
        return equal;
    return greater;
}

/*-------------------------------------------------------------------------------------
	Function		: onGetKeyName
	In Parameters	: void* keyPtr - key pointer
	Out Parameters	: const TCHAR* - key name
	Purpose			: Get key name
	Author			: Dipali
--------------------------------------------------------------------------------------*/
static TCHAR keyName_tLongToString[30];
const TCHAR* tLongToString::onGetKeyName(void* keyPtr)
{
    swprintf(keyName_tLongToString, _countof(keyName_tLongToString),_T("%li"), (long)keyPtr);
    return (const TCHAR*)keyName_tLongToString;
}

/*-------------------------------------------------------------------------------------
	Function		: onStore
	In Parameters	: void* where - destination
					  POSITION node - node
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Store one item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tLongToString::onStore(void* where, POSITION node)
{
    long key = (long)getKey(node);
    int ok = streamWrite((NQ wostream*)where, (void*)&key, sizeof(key));
    if (ok)
    {
        const TCHAR* string = (const TCHAR*)getData(node);
        long len = long(wcslen(string) + 1);
        m_bufSize = __max(m_bufSize, len);
        ok = streamWrite((NQ wostream*)where, (void*)string, len);
    }
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: onLoad
	In Parameters	: void* where - source
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Load the next item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tLongToString::onLoad(void* where)
{
    long key;
    long dLen;
    int ok = streamRead((NQ wistream*)where, (TCHAR*)&key, sizeof(key));
    if (ok)
    {
        ok = streamRead((NQ wistream*)where, (TCHAR*)m_dataBuf, m_bufSize, dLen);
        if (ok)
            ok = Set(key, (const TCHAR*)m_dataBuf);
    }
    return ok;
}

// Derived tree class: tLongToULong

/*-------------------------------------------------------------------------------------
	Function		: ~tLongToULong
	In Parameters	: -
	Out Parameters	: -
	Purpose			: destructor.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
tLongToULong::~tLongToULong()
{
    RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: onDeleteKey
	In Parameters	: void*& keyPtr - key pointer
	Out Parameters	: -
	Purpose			: delete key.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void tLongToULong::onDeleteKey(void*& keyPtr)
{
}

/*-------------------------------------------------------------------------------------
	Function		: onDeleteData
	In Parameters	: void*& dataPtr - data pointer
	Out Parameters	: -
	Purpose			: delete data.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void tLongToULong::onDeleteData(void*& dataPtr)
{
}

/*-------------------------------------------------------------------------------------
	Function		: onSetKey
	In Parameters	: void*& keyPtr - destination key pointer
					  void* key - source key
	Out Parameters	: int - 1 successful
	Purpose			: set key.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tLongToULong::onSetKey(void*& keyPtr, void* key)
{
    keyPtr = key;
    return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: onSetData
	In Parameters	: void*& dataPtr - data pointer
					  void* data - source data
	Out Parameters	: int - 1 successful
	Purpose			: Set data
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tLongToULong::onSetData(void*& dataPtr, void* data)
{
    dataPtr = data;
    return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: onCompareKeys
	In Parameters	: void* key1 - first key
					  void* key2 - second key
	Out Parameters	: relativeKeyValue - relative key
	Purpose			: compare keys
	Author			: Dipali
--------------------------------------------------------------------------------------*/
tLongToULong::relativeKeyValue tLongToULong::onCompareKeys(void* key1, void* key2)
{
    if ((long)key1 < (long)key2)
        return less;
    if ((long)key1 == (long)key2)
        return equal;
    return greater;
}

/*-------------------------------------------------------------------------------------
	Function		: onGetKeyName
	In Parameters	: void* keyPtr - key pointer
	Out Parameters	: const TCHAR* - key name
	Purpose			: Get key name
	Author			: Dipali
--------------------------------------------------------------------------------------*/
static TCHAR keyName_tLongToULong[30];
const TCHAR* tLongToULong::onGetKeyName(void* keyPtr)
{
    swprintf(keyName_tLongToULong, _countof(keyName_tLongToULong),_T("%li"), (long)keyPtr);
    return (const TCHAR*)keyName_tLongToULong;
}

/*-------------------------------------------------------------------------------------
	Function		: onStore
	In Parameters	: void* where - destination
					  POSITION node - node
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Store one item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tLongToULong::onStore(void* where, POSITION node)
{
    long key = (long)getKey(node);
    int ok = streamWrite((NQ wostream*)where, (void*)&key, sizeof(key));
    if (ok)
    {
        unsigned long data = (unsigned long)getData(node);
        ok = streamWrite((NQ wostream*)where, (void*)&data, sizeof(data));
    }
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: onLoad
	In Parameters	: void* where - source
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Load the next item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tLongToULong::onLoad(void* where)
{
    long key;
    unsigned long data;
    int ok = streamRead((NQ wistream*)where, (TCHAR*)&key, sizeof(key));
    if (ok)
    {
        ok = streamRead((NQ wistream*)where, (TCHAR*)&data, sizeof(data));
        if (ok)
            ok = Set(key, data);
    }
    return ok;
}
