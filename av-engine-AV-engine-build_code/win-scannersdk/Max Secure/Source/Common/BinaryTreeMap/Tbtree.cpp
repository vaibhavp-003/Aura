/*======================================================================================
   FILE			: tbtree.cpp 
   ABSTRACT		: implementation of abstract base class for balanced binary trees
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


#include "tbtree.h"                     // class header
#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning(disable: 6011)
#endif

/*-------------------------------------------------------------------------------------
	Function		: tBalTree
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Construction
	Author			: Dipali
--------------------------------------------------------------------------------------*/
tBalTree::tBalTree()
{
    m_imbalance = LONG_MAX;             // empirically determined default
    m_root = 0;                         // tree initially empty
    ResetStatistics();                  // no-op in debug build
}

/*-------------------------------------------------------------------------------------
	Function		: ~tBalTree
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Destruction.  
	NOTE			: All derived classes MUST call RemoveAll() in their
					  destructor in order for dynamically allocated storage to be freed.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
tBalTree::~tBalTree()
{
    ASSERT(!m_root);    // derived class did not call RemoveAll() in dtor
}

/*-------------------------------------------------------------------------------------
	Function		: RemoveAll
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Empties the tree.  
	NOTE			: All derived classes MUST call this member in
					  their destructor in order for dynamically allocated storage to be freed.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void tBalTree::RemoveAll(void)
{
    if (!m_root)
        return;
	tBalTreeNode* temp;
	tBalTreeNode* cur = m_root;
	m_root = 0;
	while (cur)
	{
		// find a leaf.
		while (cur->m_leftSubtree || cur->m_rightSubtree)
		{
			if (cur->m_leftSubtree)
				cur = cur->m_leftSubtree;
			else
				cur = cur->m_rightSubtree;
		}
		// keep leaf pointer, move to parent, reset parent's leaf-ptr.
		temp = cur;
		cur = cur->m_parent;
		if (cur)
		{
			if (cur->m_leftSubtree == temp)
				cur->m_leftSubtree = 0;
			else
				cur->m_rightSubtree = 0;
		}
		// delete the disconnected leaf.
        if (temp->m_nodeKey)
            onDeleteKey((void*&)temp->m_nodeKey);
        if (temp->m_nodeData)
            onDeleteData((void*&)temp->m_nodeData);
		free(temp);
	}
}

/*-------------------------------------------------------------------------------------
	Function		: SetAutoBalance
	In Parameters	: long maxImbalance - maximim level of imbalance
	Out Parameters	: long				- old value
	Purpose			: Sets the maximum level of imbalance allowed before an autobalance
					  operation is performed.  Returns the previous setting.  To disable
					  autobalance, pass 0.  
	Author			: Dipali
--------------------------------------------------------------------------------------*/
long tBalTree::SetAutoBalance(long maxImbalance)
{
    long oldValue = m_imbalance;
    if (oldValue == LONG_MAX)
        oldValue = 0;
    ASSERT(maxImbalance > -1);
    if (maxImbalance == 0)
        maxImbalance = LONG_MAX;
    if (maxImbalance > -1)
        m_imbalance = maxImbalance;
    return oldValue;
}

/*-------------------------------------------------------------------------------------
	Function		: Balance
	In Parameters	: int force - 0 - balance parameter
	Out Parameters	: -
	Purpose			: Performs a full tree rebalance.  If the "force" parameter is nonzero,
					  the rebalance is performed regardless of whether it is needed.  If the
					  "force" parameter is zero, the rebalance is performed only if the top
					  level of the tree is imbalanced; note that it is possible for the top
					  level to be in balance while some subtrees are extremely imbalanced.  
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tBalTree::Balance(int force)
{
    int didBalance = 0;
    if (m_root)
    {
        if (force || nodeNeedsBalance(m_root))
        {
            STAT_UPDATE(m_nBalManual);
            nodeBalance(m_root);
            didBalance = 1;
        }
    }
    return didBalance;
}

/*-------------------------------------------------------------------------------------
	Function		: Set
	In Parameters	: void* key - Key
					  void* data - data
	Out Parameters	: int - Return 1 if success,
							OR 0 if memory failure.
	Purpose			: Set routine for use by derived classes.  
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tBalTree::set(void* key, void* data)
{
    STAT_UPDATE(m_nSet);
    if (!m_root)                        // empty tree, create first node
    {
        m_root = nodeCreate(key, data);
        return m_root ? 1 : 0;
    }
    int ok = 1;                         // only out-of-memory causes failure
    tBalTreeNode* added = 0;
    tBalTreeNode* cur = m_root;
    relativeKeyValue where = undefined;
    
    // Find proper location for node and add/replace.
    while (where != equal)
    {
        where = onCompareKeys(key, cur->m_nodeKey);
        if (where == equal)                     // this item, replace data
        {
            if (cur->m_nodeData)
                onDeleteData((void*&)cur->m_nodeData);
            onSetData((void*&)cur->m_nodeData, data);
        }
        else if (where == less)
        {
            if (!cur->m_leftSubtree)
            {
                added = nodeCreate(key, data);
                if (added)
                    nodeSetLeftChild(cur, added);
                else
                    ok = 0;                     // allocation failure
                where = equal;
            }
            else
                cur = cur->m_leftSubtree;
        }
        else    // where == greater
        {
            if (!cur->m_rightSubtree)
            {
                added = nodeCreate(key, data);
                if (added)
                    nodeSetRightChild(cur, added);
                else
                    ok = 0;                     // allocation failure
                where = equal;
            }
            else
                cur = cur->m_rightSubtree;
        }
    }
    if (added && cur)
        nodeUpdateBalance(cur);
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: nodeBalance
	In Parameters	: tBalTreeNode* node - Root node
	Out Parameters	: -
	Purpose			: Balance the subtree below the specified node.  Note that this is a full
					  rebalance of the subtree whether it needs it or not.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void tBalTree::nodeBalance(tBalTreeNode* node)
{
    ASSERT(node);
    long nodes = nodeGetCount(node);
    if (nodes > 2)
    {
		// Get the new balance point of the subtree, and set it
        // as the result.
        tBalTreeNode* owner = node->m_parent;
        tBalTreeNode* root = nodeMakeBalancePoint(node);
        if (!owner)
            m_root = root;
        else
        {
            if (owner->m_leftSubtree == node)
                nodeSetLeftChild(owner, root);
            else
                nodeSetRightChild(owner, root);
        }
        // Put any qualifying left or right subtree pointers on the
        // stack.
        tBalTreeNode* stack[sizeof(long) * 8];  // enough for LONG_MAX nodes
        int stackIx = 0;
        if (root->m_leftSubtree && nodeGetCount(root->m_leftSubtree) > 2)
            stack[stackIx++] = root->m_leftSubtree;
        if (root->m_rightSubtree && nodeGetCount(root->m_rightSubtree) > 2)
            stack[stackIx++] = root->m_rightSubtree;
        // Balance from the stack until it becomes empty.
        tBalTreeNode* cur;
        tBalTreeNode* parent;
        tBalTreeNode* temp;
        while (stackIx)
        {
            cur = stack[--stackIx];
            parent = cur->m_parent;
            temp = nodeMakeBalancePoint(cur);
            if (parent->m_leftSubtree == cur)
                nodeSetLeftChild(parent, temp);
            else
                nodeSetRightChild(parent, temp);
            if (temp->m_leftSubtree && nodeGetCount(temp->m_leftSubtree) > 2)
                stack[stackIx++] = temp->m_leftSubtree;
            if (temp->m_rightSubtree && nodeGetCount(temp->m_rightSubtree) > 2)
                stack[stackIx++] = temp->m_rightSubtree;
        }
    }
}

/*-------------------------------------------------------------------------------------
	Function		: nodeRemove
	In Parameters	: tBalTreeNode* node - node
	Out Parameters	: -
	Purpose			: Remove the specified node from the tree, reorganizing and rebalancing
					  the tree as necessary.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void tBalTree::nodeRemove(tBalTreeNode* node)
{
    ASSERT(node);
    if (node)
    {
        tBalTreeNode* parent = node->m_parent;
        tBalTreeNode* child = 0;
        tBalTreeNode* topImbal = 0;
        // Combine the left/right subtrees of item being removed.
        if (node->m_leftSubtree || node->m_rightSubtree)  // not a leaf
        {
            // Heavier subtree becomes parent of lighter subtree.
            if (node->m_leftNodeCount > node->m_rightNodeCount)
            {
                if (node->m_rightSubtree)
                    topImbal = nodeInsertRightmost(node->m_leftSubtree, node->m_rightSubtree);
                child = node->m_leftSubtree;
            }
            else
            {
                if (node->m_leftSubtree)
                    topImbal = nodeInsertLeftmost(node->m_rightSubtree, node->m_leftSubtree);
                child = node->m_rightSubtree;
            }
            if (child)
                child->m_parent = 0;    // no parent link to deleted
        }
        else
            child = 0;                  // removing a leaf
        // "child" now contains combined subtree, insert it in parent.
        if (parent)
        {
            if (parent->m_leftSubtree == node)
                nodeSetLeftChild(parent, child);
            else
                nodeSetRightChild(parent, child);
        }
        else
            m_root = child;     // removing root node, child becomes new root
        // Node removed from tree, now delete it.
        if (node->m_nodeKey)
            onDeleteKey((void*&)node->m_nodeKey);
        if (node->m_nodeData)
            onDeleteData((void*&)node->m_nodeData);
        free(node);
        // Correct any imbalance introduced by removal.
        if (!topImbal)
            topImbal = parent;
        if (topImbal)
            nodeUpdateBalance(topImbal);
    }
}

/*-------------------------------------------------------------------------------------
	Function		: dumpStructure
	In Parameters	: tBalTreeNode* node - root node
					  int level - level to dump
	Out Parameters	: -
	Purpose			: Output structure recursively; called by DumpStructure().
	Author			: Dipali
--------------------------------------------------------------------------------------*/
void tBalTree::dumpStructure(tBalTreeNode* node, int level)
{
    #ifdef _DEBUG
        if (!level)
            TRACE("..........right..........\n");
        if (node->m_rightSubtree)
            dumpStructure(node->m_rightSubtree, level+1);
        TCHAR temp[100];
        for (int i=0; i<__min(level,99); i++)
            temp[i] = ' ';
        temp[__min(level,99)] = 0;
        TCHAR* info = getNodeInfo(node);
        TRACE(_T("%06li %s%s\n"), GetItemIndex((POSITION)node), temp, info);
        free(info);
        if (node->m_leftSubtree)
            dumpStructure(node->m_leftSubtree, level+1);
        if (!level)
            TRACE("..........left..........\n");
    #endif
}

/*-------------------------------------------------------------------------------------
	Function		: getNodeInfo
	In Parameters	: tBalTreeNode* node - root node
	Out Parameters	: TCHAR * = information
	Purpose			: Debug support routine called by DumpStructure().
	Note			: caller must free() the result when it is no longer needed.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
TCHAR* tBalTree::getNodeInfo(tBalTreeNode* node)
{
    ASSERT(node);
    TCHAR* temp = 0;
    #ifdef _DEBUG
        const TCHAR* keyName = 0;
        if (node->m_nodeKey)
            keyName = _wcsdup(onGetKeyName(node->m_nodeKey));
        int len = keyName ? (int)wcslen(keyName) : 0;
        const TCHAR* parent = _T("NOPARENT");
        if (node->m_parent)
            if (node->m_parent->m_nodeKey)
                parent = onGetKeyName(node->m_parent->m_nodeKey);
        len += (int)wcslen(parent);
        temp = (TCHAR*)malloc(len + 30);
        swprintf(temp, len + 30, _T("%li,%li=%s (parent=%s)"), node->m_leftNodeCount, 
                node->m_rightNodeCount, keyName, parent);
        free((void*)keyName);
    #endif
    return temp;
}


/*-------------------------------------------------------------------------------------
	Function		: onGetKeyName
	In Parameters	: void* keyPtr - key
	Out Parameters	: TCHAR * = ASCII key
	Purpose			: Return a pointer to ASCII representation of the key's name.  
					  The pointer returned may refer to a static buffer.
					  Used by the DumpStructure() member.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
static TCHAR nameBuf[12];
const TCHAR* tBalTree::onGetKeyName(void* keyPtr)
{
    swprintf(nameBuf, _countof(nameBuf),_T("%p"), keyPtr);
    return nameBuf;
}

/*-------------------------------------------------------------------------------------
	Function		: Store
	In Parameters	: NQ wostream* ostrm - oStream
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Serialize the tree to an ostream.  
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tBalTree::Store(NQ wostream* ostrm)
{
    int ok = 0;
    if (ostrm && ostrm->good())
    {
        // first write empty header and note its position.
        m_bufSize = 0;              // initialize max buffer size required
        NQ streampos posHdr = ostrm->tellp();
        StrmHdr hdr;
        hdr.segLength = 0;
        hdr.segBufReqd = 0;
        ok = streamWrite(ostrm, &hdr, sizeof(hdr));
        
        // now serialize the tree.
        if (ok)
            ok = storeTree((void*)ostrm);
        
        // if successful update the header.
        if (ok)
        {
            hdr.segBufReqd = m_bufSize;
            NQ streampos posEnd = ostrm->tellp();
            hdr.segLength = (long)posEnd - (long)posHdr;
            ostrm->seekp(posHdr);
            ok = streamWrite(ostrm, &hdr, sizeof(hdr));
            ostrm->seekp(posEnd);
        }
    }
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: storeTree
	In Parameters	: void* where - destination
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: For each item in the tree, call the onStore() virtual.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tBalTree::storeTree(void* where)
{
    int ok = 0;
	if (m_root)
	{
		tBalTreeNode* stack[sizeof(long) * 8];  // enoung for LONG_MAX nodes
		int stackIx = 0;
		stack[stackIx++] = m_root;
		tBalTreeNode* next;
		while (stackIx)
		{
			next = stack[--stackIx];
			ok = onStore(where, (POSITION)next);
			if (!ok)
				break;
			if (next->m_leftSubtree)
				stack[stackIx++] = next->m_leftSubtree;
			if (next->m_rightSubtree)
				stack[stackIx++] = next->m_rightSubtree;
		}
	}
    return ok;
}


/*-------------------------------------------------------------------------------------
	Function		: Load
	In Parameters	: NQ wistream* istrm - istream
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Serialize the tree from an istream.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tBalTree::Load(NQ wistream* istrm)
{
    RemoveAll();
    long imbalance = SetAutoBalance(0);     // turn off autobalance
    long posHdr = (long)istrm->tellg();
    StrmHdr hdr;
    int ok = streamRead(istrm, (void*)&hdr, sizeof(hdr));
    if (ok)
    {
        m_bufSize = hdr.segBufReqd;
        m_keyBuf = m_dataBuf = 0;
        if (m_bufSize > 0)
        {
            m_keyBuf = malloc((size_t)m_bufSize);
            m_dataBuf = malloc((size_t)m_bufSize);
            if (!m_keyBuf || !m_dataBuf)
                ok = 0;
        }
        if (ok)
        {
            long posEnd = posHdr + hdr.segLength;
            while (ok && (long)istrm->tellg() < posEnd && !istrm->eof())
                ok = onLoad((void*)istrm);
        }
        free(m_keyBuf);
        free(m_dataBuf);
    }
    SetAutoBalance(imbalance);              // resume autobalance
    return ok;
}

/*-------------------------------------------------------------------------------------
	Function		: onStore
	In Parameters	: void* where - destination
					  POSITION node - node
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Store one item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tBalTree::onStore(void* where, POSITION node)
{
    return 0;   // no-op unless overridden in derived class
}

/*-------------------------------------------------------------------------------------
	Function		: onLoad
	In Parameters	: void* where - source
	Out Parameters	: int - Returns 1 if success else 0.
	Purpose			: Load the next item during serialization.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int tBalTree::onLoad(void* where)
{
    return 0;   // no-op unless overridden in derived class
}
#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning (default:6011)
#endif