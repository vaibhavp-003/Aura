/*======================================================================================
   FILE			: tbtreed.h 
   ABSTRACT		: header file
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
#ifndef _tbtreed_h_
#define _tbtreed_h_

#ifndef _tbtree_h_
#include "tbtree.h"
#endif
#pragma warning(disable: 4312)
#pragma warning(disable: 4311)

// Derived tree class: string key, string data
class EXT_CLASS tStringToString : public tBalTree
{
public:
    virtual ~tStringToString();
    inline int Set(const TCHAR * key, const TCHAR * data);
    inline const TCHAR* Get(const TCHAR* key);
    inline const TCHAR* GetKey(POSITION pos);
    inline const TCHAR* GetData(POSITION pos);
    inline int SetData(POSITION pos, const TCHAR* data);
    inline POSITION Find(const TCHAR* key);
    inline int Remove(const TCHAR* key);
    inline int Remove(POSITION& pos);
    
protected:
    // These members required in all derived classes:
    virtual void onDeleteKey(void*& keyPtr);
    virtual void onDeleteData(void*& dataPtr);
    virtual int onSetKey(void*& keyPtr, void* key);
    virtual int onSetData(void*& dataPtr, void* data);
    virtual relativeKeyValue onCompareKeys(void* key1, void* key2);
    
    // This member provided for debugging support:
    virtual const TCHAR* onGetKeyName(void* keyPtr);
    
    // These members provide serialization to iostreams:
    virtual int onStore(void* where, POSITION node);    // output 1 node
    virtual int onLoad(void* where);                    // input 1 node
};


// Derived tree class: string key, unsigned long data
class EXT_CLASS tStringToULong : public tBalTree
{
public:
    virtual ~tStringToULong();
    inline int Set(const TCHAR * key, unsigned long data);
    inline unsigned long Get(const TCHAR* key);
    inline const TCHAR* GetKey(POSITION pos);
    inline unsigned long GetData(POSITION pos);
    inline int SetData(POSITION pos, unsigned long data);
    inline POSITION Find(const TCHAR* key);
    inline int Remove(const TCHAR* key);
    inline int Remove(POSITION& pos);
    
protected:
    // These members required in all derived classes:
    virtual void onDeleteKey(void*& keyPtr);
    virtual void onDeleteData(void*& dataPtr);
    virtual int onSetKey(void*& keyPtr, void* key);
    virtual int onSetData(void*& dataPtr, void* data);
    virtual relativeKeyValue onCompareKeys(void* key1, void* key2);
    
    // This member provided for debugging support:
    virtual const TCHAR* onGetKeyName(void* keyPtr);
    
    // These members provide serialization to iostreams:
    virtual int onStore(void* where, POSITION node);    // output 1 node
    virtual int onLoad(void* where);                    // input 1 node
};


// Derived tree class: unsigned long key, string data
class EXT_CLASS tULongToString : public tBalTree
{
public:
    virtual ~tULongToString();
    inline int Set(unsigned long key, const TCHAR * data);
    inline const TCHAR* Get(unsigned long key);
    inline unsigned long GetKey(POSITION pos);
    inline const TCHAR* GetData(POSITION pos);
    inline int SetData(POSITION pos, const TCHAR* data);
    inline POSITION Find(unsigned long key);
    inline int Remove(unsigned long key);
    inline int Remove(POSITION& pos);
    
protected:
    // These members required in all derived classes:
    virtual void onDeleteKey(void*& keyPtr);
    virtual void onDeleteData(void*& dataPtr);
    virtual int onSetKey(void*& keyPtr, void* key);
    virtual int onSetData(void*& dataPtr, void* data);
    virtual relativeKeyValue onCompareKeys(void* key1, void* key2);
    
    // This member provided for debugging support:
    virtual const TCHAR* onGetKeyName(void* keyPtr);
    
    // These members provide serialization to iostreams:
    virtual int onStore(void* where, POSITION node);    // output 1 node
    virtual int onLoad(void* where);                    // input 1 node
};


// Derived tree class: unsigned long key, unsigned long data
class EXT_CLASS tULongToULong : public tBalTree
{
public:
    virtual ~tULongToULong();
    inline int Set(unsigned long key, unsigned long data);
    inline unsigned long Get(unsigned long key);
    inline unsigned long GetKey(POSITION pos);
    inline unsigned long GetData(POSITION pos);
    inline int SetData(POSITION pos, unsigned long data);
    inline POSITION Find(unsigned long key);
    inline int Remove(unsigned long key);
    inline int Remove(POSITION& pos);
    
protected:
    // These members required in all derived classes:
    virtual void onDeleteKey(void*& keyPtr);
    virtual void onDeleteData(void*& dataPtr);
    virtual int onSetKey(void*& keyPtr, void* key);
    virtual int onSetData(void*& dataPtr, void* data);
    virtual relativeKeyValue onCompareKeys(void* key1, void* key2);
    
    // This member provided for debugging support:
    virtual const TCHAR* onGetKeyName(void* keyPtr);
    
    // These members provide serialization to iostreams:
    virtual int onStore(void* where, POSITION node);    // output 1 node
    virtual int onLoad(void* where);                    // input 1 node
};


// Derived tree class: long key, string data
class EXT_CLASS tLongToString : public tBalTree
{
public:
    virtual ~tLongToString();
    inline int Set(long key, const TCHAR * data);
    inline const TCHAR* Get(long key);
    inline long GetKey(POSITION pos);
    inline const TCHAR* GetData(POSITION pos);
    inline int SetData(POSITION pos, const TCHAR* data);
    inline POSITION Find(long key);
    inline int Remove(long key);
    inline int Remove(POSITION& pos);
    
protected:
    // These members required in all derived classes:
    virtual void onDeleteKey(void*& keyPtr);
    virtual void onDeleteData(void*& dataPtr);
    virtual int onSetKey(void*& keyPtr, void* key);
    virtual int onSetData(void*& dataPtr, void* data);
    virtual relativeKeyValue onCompareKeys(void* key1, void* key2);
    
    // This member provided for debugging support:
    virtual const TCHAR* onGetKeyName(void* keyPtr);
    
    // These members provide serialization to iostreams:
    virtual int onStore(void* where, POSITION node);    // output 1 node
    virtual int onLoad(void* where);                    // input 1 node
};


// Derived tree class: long key, unsigned long data
class EXT_CLASS tLongToULong : public tBalTree
{
public:
    virtual ~tLongToULong();
    inline int Set(long key, unsigned long data);
    inline unsigned long Get(long key);
    inline long GetKey(POSITION pos);
    inline unsigned long GetData(POSITION pos);
    inline int SetData(POSITION pos, unsigned long data);
    inline POSITION Find(long key);
    inline int Remove(long key);
    inline int Remove(POSITION& pos);
    
protected:
    // These members required in all derived classes:
    virtual void onDeleteKey(void*& keyPtr);
    virtual void onDeleteData(void*& dataPtr);
    virtual int onSetKey(void*& keyPtr, void* key);
    virtual int onSetData(void*& dataPtr, void* data);
    virtual relativeKeyValue onCompareKeys(void* key1, void* key2);
    
    // This member provided for debugging support:
    virtual const TCHAR* onGetKeyName(void* keyPtr);
    
    // These members provide serialization to iostreams:
    virtual int onStore(void* where, POSITION node);    // output 1 node
    virtual int onLoad(void* where);                    // input 1 node
};


// INLINE members for all classes defined here.

// tStringToString
/*-------------------------------------------------------------------------------------
	Function		: Set
	In Parameters	: const TCHAR * key - Key
					  const TCHAR * data - data
	Out Parameters	: int - status
	Purpose			: Set key and data
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tStringToString::Set(const TCHAR * key, const TCHAR * data)
{
    return set((void*)key, (void*)data);
}

/*-------------------------------------------------------------------------------------
	Function		: Get
	In Parameters	: const TCHAR * key - Key
	Out Parameters	: const TCHAR * data - data
	Purpose			: Get data for given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline const TCHAR* tStringToString::Get(const TCHAR* key)
{
    return (const TCHAR*)getData(find((void*)key));
}

/*-------------------------------------------------------------------------------------
	Function		: Find
	In Parameters	: const TCHAR* Key - Key
	Out Parameters	: POSITION - position of given key
	Purpose			: find position of given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline POSITION tStringToString::Find(const TCHAR* key)
{
    return (POSITION)find((void*)key);
}

/*-------------------------------------------------------------------------------------
	Function		: SetData
	In Parameters	: POSITION node - position
					  const TCHAR* data - data
	Out Parameters	: int - successful or not
	Purpose			: Set data at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tStringToString::SetData(POSITION node, const TCHAR* data)
{
    return setData(node, (void*)data);
}

/*-------------------------------------------------------------------------------------
	Function		: Remove
	In Parameters	: const TCHAR* Key - Key
	Out Parameters	: int - successful or not
	Purpose			: remove given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tStringToString::Remove(const TCHAR* key)
{
    POSITION pos = find((void*)key);
    int ok = pos ? 1 : 0;
    remove(pos);
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: Remove
	In Parameters	: POSITION& pos - position
	Out Parameters	: int - successful or not
	Purpose			: remove node at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tStringToString::Remove(POSITION& pos)
{
    int ok = pos ? 1 : 0;
    remove(pos);
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: GetKey
	In Parameters	: POSITION pos - position
	Out Parameters	: const TCHAR* - key
	Purpose			: Get key at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline const TCHAR* tStringToString::GetKey(POSITION pos)
{
    return (const TCHAR*)getKey(pos);
}

/*-------------------------------------------------------------------------------------
	Function		: GetData
	In Parameters	: POSITION pos - position
	Out Parameters	: const TCHAR* - data
	Purpose			: Get data at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline const TCHAR* tStringToString::GetData(POSITION pos)
{
    return (const TCHAR*)getData(pos);
}


// tStringToULong
/*-------------------------------------------------------------------------------------
	Function		: Set
	In Parameters	: const TCHAR * key - Key
					  unsigned long data - data
	Out Parameters	: int - status
	Purpose			: Set key and data
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tStringToULong::Set(const TCHAR * key, unsigned long data)
{
    return set((void*)key, (void*)data);
}

/*-------------------------------------------------------------------------------------
	Function		: Get
	In Parameters	: const TCHAR * key - Key
	Out Parameters	: unsigned long - data
	Purpose			: Get data for given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline unsigned long tStringToULong::Get(const TCHAR* key)
{
    return (unsigned long)getData(find((void*)key));
}

/*-------------------------------------------------------------------------------------
	Function		: SetData
	In Parameters	: POSITION node - position
					  unsigned long data - data
	Out Parameters	: int - successful or not
	Purpose			: Set data at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tStringToULong::SetData(POSITION node, unsigned long data)
{
    return setData(node, (void*)data);
}

/*-------------------------------------------------------------------------------------
	Function		: Find
	In Parameters	: const TCHAR* Key - Key
	Out Parameters	: POSITION - position of given key
	Purpose			: find position of given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline POSITION tStringToULong::Find(const TCHAR* key)
{
    return (POSITION)find((void*)key);
}

/*-------------------------------------------------------------------------------------
	Function		: Remove
	In Parameters	: const TCHAR* Key - Key
	Out Parameters	: int - successful or not
	Purpose			: remove given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tStringToULong::Remove(const TCHAR* key)
{
    POSITION pos = find((void*)key);
    int ok = pos ? 1 : 0;
    remove(pos);
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: Remove
	In Parameters	: POSITION& pos - position
	Out Parameters	: int - successful or not
	Purpose			: remove node at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tStringToULong::Remove(POSITION& pos)
{
    int ok = pos ? 1 : 0;
    remove(pos);
	return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: GetKey
	In Parameters	: POSITION pos - position
	Out Parameters	: const TCHAR* - key
	Purpose			: Get key at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline const TCHAR* tStringToULong::GetKey(POSITION pos)
{
    return (const TCHAR*)getKey(pos);
}

/*-------------------------------------------------------------------------------------
	Function		: GetData
	In Parameters	: POSITION pos - position
	Out Parameters	: unsigned long  - data
	Purpose			: Get data at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline unsigned long tStringToULong::GetData(POSITION pos)
{
    return (unsigned long)getData(pos);
}


// tULongToString
/*-------------------------------------------------------------------------------------
	Function		: Set
	In Parameters	: unsigned long  key - Key
					  const TCHAR * data - data
	Out Parameters	: int - status
	Purpose			: Set key and data
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tULongToString::Set(unsigned long key, const TCHAR * data)
{
    return set((void*)key, (void*)data);
}

/*-------------------------------------------------------------------------------------
	Function		: Get
	In Parameters	: unsigned long key - Key
	Out Parameters	: const TCHAR* - data
	Purpose			: Get data for given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline const TCHAR* tULongToString::Get(unsigned long key)
{
    return (const TCHAR*)getData(find((void*)key));
}

/*-------------------------------------------------------------------------------------
	Function		: SetData
	In Parameters	: POSITION node - position
					  const TCHAR* data - data
	Out Parameters	: int - successful or not
	Purpose			: Set data at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tULongToString::SetData(POSITION node, const TCHAR* data)
{
    return setData(node, (void*)data);
}

/*-------------------------------------------------------------------------------------
	Function		: Find
	In Parameters	: unsigned long Key - Key
	Out Parameters	: POSITION - position of given key
	Purpose			: find position of given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline POSITION tULongToString::Find(unsigned long key)
{
    return (POSITION)find((void*)key);
}

/*-------------------------------------------------------------------------------------
	Function		: Remove
	In Parameters	: unsigned long Key - Key
	Out Parameters	: int - successful or not
	Purpose			: remove given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tULongToString::Remove(unsigned long key)
{
    POSITION pos = find((void*)key);
    int ok = pos ? 1 : 0;
    remove(pos);
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: Remove
	In Parameters	: POSITION& pos - position
	Out Parameters	: int - successful or not
	Purpose			: remove node at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tULongToString::Remove(POSITION& pos)
{
    int ok = pos ? 1 : 0;
    remove(pos);
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: GetKey
	In Parameters	: POSITION pos - position
	Out Parameters	: unsigned long - key
	Purpose			: Get key at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline unsigned long tULongToString::GetKey(POSITION pos)
{
    return (unsigned long)getKey(pos);
}

/*-------------------------------------------------------------------------------------
	Function		: GetData
	In Parameters	: POSITION pos - position
	Out Parameters	: const TCHAR*  - data
	Purpose			: Get data at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline const TCHAR* tULongToString::GetData(POSITION pos)
{
    return (const TCHAR*)getData(pos);
}


// tULongToULong
/*-------------------------------------------------------------------------------------
	Function		: Set
	In Parameters	: unsigned long  key - Key
					  unsigned long data - data
	Out Parameters	: int - status
	Purpose			: Set key and data
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tULongToULong::Set(unsigned long key, unsigned long data)
{
    return set((void*)key, (void*)data);
}

/*-------------------------------------------------------------------------------------
	Function		: Get
	In Parameters	: unsigned long key - Key
	Out Parameters	: unsigned long - data
	Purpose			: Get data for given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline unsigned long tULongToULong::Get(unsigned long key)
{
    return (unsigned long)getData(find((void*)key));
}

/*-------------------------------------------------------------------------------------
	Function		: SetData
	In Parameters	: POSITION node - position
					  unsigned long data - data
	Out Parameters	: int - successful or not
	Purpose			: Set data at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tULongToULong::SetData(POSITION node, unsigned long data)
{
    return setData(node, (void*)data);
}

/*-------------------------------------------------------------------------------------
	Function		: Find
	In Parameters	: unsigned long Key - Key
	Out Parameters	: POSITION - position of given key
	Purpose			: find position of given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline POSITION tULongToULong::Find(unsigned long key)
{
    return (POSITION)find((void*)key);
}

/*-------------------------------------------------------------------------------------
	Function		: Remove
	In Parameters	: unsigned long Key - Key
	Out Parameters	: int - successful or not
	Purpose			: remove given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tULongToULong::Remove(unsigned long key)
{
    POSITION pos = find((void*)key);
    int ok = pos ? 1 : 0;
    remove(pos);
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: Remove
	In Parameters	: POSITION& pos - position
	Out Parameters	: int - successful or not
	Purpose			: remove node at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tULongToULong::Remove(POSITION& pos)
{
    int ok = pos ? 1 : 0;
    remove(pos);
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: GetKey
	In Parameters	: POSITION pos - position
	Out Parameters	: unsigned long - key
	Purpose			: Get key at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline unsigned long tULongToULong::GetKey(POSITION pos)
{
    return (unsigned long)getKey(pos);
}

/*-------------------------------------------------------------------------------------
	Function		: GetData
	In Parameters	: POSITION pos - position
	Out Parameters	: unsigned long  - data
	Purpose			: Get data at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline unsigned long tULongToULong::GetData(POSITION pos)
{
    return (unsigned long)getData(pos);
}


// tLongToString
/*-------------------------------------------------------------------------------------
	Function		: Set
	In Parameters	: long  key - Key
					  const TCHAR * - data
	Out Parameters	: int - status
	Purpose			: Set key and data
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tLongToString::Set(long key, const TCHAR * data)
{
    return set((void*)key, (void*)data);
}

/*-------------------------------------------------------------------------------------
	Function		: Get
	In Parameters	: long key - Key
	Out Parameters	: const TCHAR* - data
	Purpose			: Get data for given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline const TCHAR* tLongToString::Get(long key)
{
    return (const TCHAR*)getData(find((void*)key));
}

/*-------------------------------------------------------------------------------------
	Function		: SetData
	In Parameters	: POSITION node - position
					  const TCHAR* data - data
	Out Parameters	: int - successful or not
	Purpose			: Set data at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tLongToString::SetData(POSITION node, const TCHAR* data)
{
    return setData(node, (void*)data);
}

/*-------------------------------------------------------------------------------------
	Function		: Find
	In Parameters	: long Key - Key
	Out Parameters	: POSITION - position of given key
	Purpose			: find position of given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline POSITION tLongToString::Find(long key)
{
    return (POSITION)find((void*)key);
}

/*-------------------------------------------------------------------------------------
	Function		: Remove
	In Parameters	: long Key - Key
	Out Parameters	: int - successful or not
	Purpose			: remove given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tLongToString::Remove(long key)
{
    POSITION pos = find((void*)key);
    int ok = pos ? 1 : 0;
    remove(pos);
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: Remove
	In Parameters	: POSITION& pos - position
	Out Parameters	: int - successful or not
	Purpose			: remove node at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tLongToString::Remove(POSITION& pos)
{
    int ok = pos ? 1 : 0;
    remove(pos);
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: GetKey
	In Parameters	: POSITION pos - position
	Out Parameters	: long - key
	Purpose			: Get key at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline long tLongToString::GetKey(POSITION pos)
{
    return (long)getKey(pos);
}

/*-------------------------------------------------------------------------------------
	Function		: GetData
	In Parameters	: POSITION pos - position
	Out Parameters	: const TCHAR*  - data
	Purpose			: Get data at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline const TCHAR* tLongToString::GetData(POSITION pos)
{
    return (const TCHAR*)getData(pos);
}

// tLongToULong
/*-------------------------------------------------------------------------------------
	Function		: Set
	In Parameters	: long  key - Key
					  unsigned long - data
	Out Parameters	: int - status
	Purpose			: Set key and data
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tLongToULong::Set(long key, unsigned long data)
{
    return set((void*)key, (void*)data);
}

/*-------------------------------------------------------------------------------------
	Function		: Get
	In Parameters	: long key - Key
	Out Parameters	: unsigned long - data
	Purpose			: Get data for given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline unsigned long tLongToULong::Get(long key)
{
    return (unsigned long)getData(find((void*)key));
}

/*-------------------------------------------------------------------------------------
	Function		: SetData
	In Parameters	: POSITION node - position
					  unsigned long data - data
	Out Parameters	: int - successful or not
	Purpose			: Set data at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tLongToULong::SetData(POSITION node, unsigned long data)
{
    return setData(node, (void*)data);
}

/*-------------------------------------------------------------------------------------
	Function		: Find
	In Parameters	: long Key - Key
	Out Parameters	: POSITION - position of given key
	Purpose			: find position of given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline POSITION tLongToULong::Find(long key)
{
    return (POSITION)find((void*)key);
}

/*-------------------------------------------------------------------------------------
	Function		: Remove
	In Parameters	: long Key - Key
	Out Parameters	: int - successful or not
	Purpose			: remove given key
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tLongToULong::Remove(long key)
{
    POSITION pos = find((void*)key);
    int ok = pos ? 1 : 0;
    remove(pos);
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: Remove
	In Parameters	: POSITION& pos - position
	Out Parameters	: int - successful or not
	Purpose			: remove node at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tLongToULong::Remove(POSITION& pos)
{
    int ok = pos ? 1 : 0;
    remove(pos);
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: GetKey
	In Parameters	: POSITION pos - position
	Out Parameters	: long - key
	Purpose			: Get key at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline long tLongToULong::GetKey(POSITION pos)
{
    return (long)getKey(pos);
}

/*-------------------------------------------------------------------------------------
	Function		: GetData
	In Parameters	: POSITION pos - position
	Out Parameters	: unsigned long  - data
	Purpose			: Get data at given position
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline unsigned long tLongToULong::GetData(POSITION pos)
{
    return (unsigned long)getData(pos);
}

#endif
