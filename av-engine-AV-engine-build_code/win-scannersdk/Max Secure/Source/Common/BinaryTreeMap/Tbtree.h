/*======================================================================================
   FILE			: tbtree.h 
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
#ifndef _tbtree_h_
#define _tbtree_h_

#ifndef _zlib_h
#include "zlib.h"
#endif

#ifndef _zserial_h_
#include "zserial.h"
#endif
#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning(disable: 6011)
#endif


// Define the STAT_UPDATE macro to update debug-build statistics
#ifdef _DEBUG
    #define STAT_UPDATE(a) a++
#else
    #define STAT_UPDATE(a)
#endif

// tBalTree class: Abstract base class for balanced binary trees.
class EXT_CLASS tBalTree : public zSerial
{
public:
    tBalTree();
    virtual ~tBalTree();
    
    long SetAutoBalance(long maxImbalance);         // pass 0 to turn off
    int Balance(int force = 0);                     // only cks top unless force
    
    void RemoveAll(void);                           // empties the tree
    
    inline long GetCount(void);                     // returns item count
    inline POSITION GetItem(long item);             // find 0-based item N
    inline long GetItemIndex(POSITION node);        // item's 0-based index
    
    inline POSITION First(void);                    // position at first
    inline POSITION Last(void);                     // position at last
    inline POSITION Prev(POSITION node);            // move to previous
    inline POSITION Next(POSITION node);            // move to next
    
    // zSerial overrides for serialization using iostreams:
    virtual int Store(NQ wostream* ostrm);              // 1 if success, else 0
    virtual int Load(NQ wistream* istrm);               // 1 if success, else 0
    
    // debugging support
    inline void DumpStructure(void);                // no-op in release build
    inline void DumpStatistics(void);               // no-op in release build
    inline void ResetStatistics(void);              // no-op in release build
    
    // statistics, available in debug build only:
    #ifdef _DEBUG
        long    m_nBalManual;       // manually performed balance operations
        long    m_nBalAuto;         // autobalance operations
        long    m_nGet;             // number of data retrieval operations
        long    m_nSet;             // number of data storage operations
    #endif
    
protected:
    // Relative key value defined same as result from strcmp() except
    // for the "undefined" value.
    enum relativeKeyValue {less = -1,
                           equal = 0,
                           greater = 1,
                           undefined = 2};
    
    // Support routines for derived classes:
    inline POSITION find(void* key);                // find specific item
    inline void* getKey(POSITION node);             // return key ptr
    inline void* getData(POSITION node);            // return data ptr
    int set(void* key, void* data);                 // 1 if success, else 0
    inline int setData(POSITION node, void* data);  // 1 if success, else 0
    inline void remove(POSITION& node);             // remove specific item
    int storeTree(void* where);                     // for serialization
    
    // Overrides required in all derived classes:
    virtual void onDeleteKey(void*& keyPtr) = 0;    // don't zero keyPtr
    virtual void onDeleteData(void*& dataPtr) = 0;  // don't zero dataPtr
    virtual int onSetKey(void*& keyPtr, void* key) = 0;    // don't delete previous
    virtual int onSetData(void*& dataPtr, void* data) = 0; // don't delete previous
    virtual relativeKeyValue onCompareKeys(void* key1, void* key2) = 0;
    
    // Optional overrides for debugging support:
    virtual const TCHAR* onGetKeyName(void* keyPtr);
    
    // Optional overrides for serialization:
    virtual int onStore(void* where, POSITION node);    // output 1 node
    virtual int onLoad(void* where);                    // input 1 node
    
    // Member variables:
    typedef struct tStrmHdr // stream header used for serialization
    {
        long segLength;     // total length of data segment incl hdr
        long segBufReqd;    // size to hold largest data item in segment
    } StrmHdr;
    
    long        m_bufSize;                  // max size for input serialization
    void*       m_keyBuf;                   // key buffer during serialization
    void*       m_dataBuf;                  // data buffer during serialization

private:
    // Node structure:
    struct tBalTreeNode
    {
        void*           m_nodeKey;
        void*           m_nodeData;
        tBalTreeNode*   m_parent;
        tBalTreeNode*   m_leftSubtree;
        long                m_leftNodeCount;
        tBalTreeNode*   m_rightSubtree;
        long                m_rightNodeCount;
    };
    
    // Other private data:
    tBalTreeNode*   m_root;
    long            m_imbalance;

    // Node-handling routines:
    void nodeBalance(tBalTreeNode* node);
    void nodeRemove(tBalTreeNode* node);
    
    inline long nodeGetCount(tBalTreeNode* node);
    inline tBalTreeNode* nodeCreate(void* key, void* data);
    inline void nodeSetLeftChild(tBalTreeNode* node, tBalTreeNode* child);
    inline void nodeSetRightChild(tBalTreeNode* node, tBalTreeNode* child);
    inline void nodeUpdateBalance(tBalTreeNode* node);
    inline int nodeNeedsBalance(tBalTreeNode* node);
    inline long nodeGetBalanceItem(long nodes);
    inline tBalTreeNode* nodeFindItem(tBalTreeNode* node, long item);
    inline tBalTreeNode* nodeInsertLeftmost(tBalTreeNode* parent,
                                            tBalTreeNode* child);
    inline tBalTreeNode* nodeInsertRightmost(tBalTreeNode* parent,
                                             tBalTreeNode* child);
    inline tBalTreeNode* nodeMakeBalancePoint(tBalTreeNode* oldRoot);
    
    // Debug support routines:
    TCHAR* getNodeInfo(tBalTreeNode* node);      // no-op in release build
    void dumpStructure(tBalTreeNode* node, int level);  // no-op in release build
};

// INLINE members.

/*-------------------------------------------------------------------------------------
	Function		: GetCount
	In Parameters	: -
	Out Parameters	: long - count
	Purpose			: Returns the total number of items in the tree.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline long tBalTree::GetCount(void)
{
    if (m_root)
        return nodeGetCount(m_root);
    return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: GetCount
	In Parameters	: -
	Out Parameters	: long - count
	Purpose			: Returns the total number of items in the subtree.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline long tBalTree::nodeGetCount(tBalTreeNode* node)
{
    ASSERT(node);
    return node->m_leftNodeCount + node->m_rightNodeCount + 1;
}

/*-------------------------------------------------------------------------------------
	Function		: nodeCreate
	In Parameters	: void* key - Key
					  void* data - data
	Out Parameters	: tBalTree::tBalTreeNode* - node
	Purpose			: Called to create a new node with the given key/data values.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline tBalTree::tBalTreeNode* tBalTree::nodeCreate(void* key, void* data)
{
    tBalTreeNode* node = (tBalTreeNode*)malloc(sizeof(tBalTreeNode));
    if (node)
    {
        memset(node, 0, sizeof(tBalTreeNode));
        if (!onSetKey((void*&)node->m_nodeKey, key))
        {
            free(node);
            node = 0;
        }
        else
        {
            if (!onSetData((void*&)node->m_nodeData, data))
            {
                onDeleteKey((void*&)node->m_nodeKey);
                free(node);
                node = 0;
            }
        }
    }
    return node;
}

/*-------------------------------------------------------------------------------------
	Function		: nodeSetLeftChild
	In Parameters	: tBalTreeNode* node - Root
					  tBalTreeNode* child - childe node
	Out Parameters	: void
	Purpose			: Sets the specified node's left child, and updates its node counts.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline void tBalTree::nodeSetLeftChild(tBalTreeNode* node, tBalTreeNode* child)
{
    ASSERT(node);
    node->m_leftSubtree = child;
    if (child)
    {
        node->m_leftNodeCount = child->m_leftNodeCount
                                + child->m_rightNodeCount
                                + 1;
        child->m_parent = node;
    }
    else
        node->m_leftNodeCount = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: nodeSetRightChild
	In Parameters	: tBalTreeNode* node - Root
					  tBalTreeNode* child - childe node
	Out Parameters	: void
	Purpose			: Sets the specified node's right child, and updates its node counts.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline void tBalTree::nodeSetRightChild(tBalTreeNode* node, tBalTreeNode* child)
{
    ASSERT(node);
    node->m_rightSubtree = child;
    if (child)
    {
        node->m_rightNodeCount = child->m_leftNodeCount
                                + child->m_rightNodeCount
                                + 1;
        child->m_parent = node;
    }
    else
        node->m_rightNodeCount = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: nodeUpdateBalance
	In Parameters	: tBalTreeNode* node - Root
	Out Parameters	: void
	Purpose			: Called when a node has been added or deleted; works back to the root
					  updating balance counts, then rebalances the topmost subtree that is
					  sufficiently imbalanced to require a rebalance (if any).
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline void tBalTree::nodeUpdateBalance(tBalTreeNode* node)
{
    ASSERT(node);
    tBalTreeNode* topImbal = 0;
    tBalTreeNode* child;
    while (node != m_root)
    {
        if (nodeNeedsBalance(node))
            topImbal = node;
        child = node;
        node = node->m_parent;
        if (node)
        {
            if (node->m_leftSubtree == child)
                nodeSetLeftChild(node, child);      // to update node counts
            else
                nodeSetRightChild(node, child);
        }
    }
    // Perform autobalance if needed.
    if (nodeNeedsBalance(m_root))
        topImbal = m_root;
    if (topImbal)
    {
        STAT_UPDATE(m_nBalAuto);
        nodeBalance(topImbal);
    }
}

/*-------------------------------------------------------------------------------------
	Function		: nodeNeedsBalance
	In Parameters	: tBalTreeNode* node - node
	Out Parameters	: void
	Purpose			: Checks the specified node's balance.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tBalTree::nodeNeedsBalance(tBalTreeNode* node)
{
    ASSERT(node);
    long diff = node->m_leftNodeCount - node->m_rightNodeCount;
    if (diff > m_imbalance)
        return 1;
    if (diff < -m_imbalance)
        return 1;
    return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: nodeGetBalanceItem
	In Parameters	: long nodes - number of nodes
	Out Parameters	: long - balanced node count
	Purpose			: Compute the item number of the balance point; localized to ensure
					  consistent computation.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline long tBalTree::nodeGetBalanceItem(long nodes)
{
    return nodes / 2;
}

/*-------------------------------------------------------------------------------------
	Function		: nodeFindItem
	In Parameters	: tBalTreeNode* node - subtree root node
                      long item - search limit
	Out Parameters	: tBalTree::tBalTreeNode* - node
	Purpose			: Given any node, find 0-based item "item" within the subtree it owns.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline tBalTree::tBalTreeNode* tBalTree::nodeFindItem(tBalTreeNode* node,
                                                      long item)
{
    ASSERT(node);
    ASSERT(item >= 0);
    ASSERT(item < nodeGetCount(node));
    tBalTreeNode* found = 0;
    while (!found)
    {
        if (node->m_leftNodeCount > item)   // node is left of this node
            node = node->m_leftSubtree;
        else if (node->m_leftNodeCount == item) // found the node requested
            found = node;
        else                                // node is right of this node
        {
            item -= node->m_leftNodeCount + 1;
            ASSERT(item >= 0);
            node = node->m_rightSubtree;
        }
    }
    return found;
}

/*-------------------------------------------------------------------------------------
	Function		: nodeInsertLeftmost
	In Parameters	: tBalTreeNode* parent - parent node
                      tBalTreeNode* child - child node
	Out Parameters	: tBalTree::tBalTreeNode* - node
	Purpose			: Insert the "child" subtree as the leftmost node of the "parent" subtree,
					  and return the topmost node that is out of balance.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline tBalTree::tBalTreeNode* tBalTree::nodeInsertLeftmost(tBalTreeNode* parent, tBalTreeNode* child)
{
    ASSERT(parent);
    ASSERT(child);
    tBalTreeNode* topImbal = 0;
    long childCount = nodeGetCount(child);
    // Move to leftmost node, updating balance on the way.
    while (parent->m_leftSubtree)
    {
        parent->m_leftNodeCount += childCount;
        if (!topImbal && nodeNeedsBalance(parent))
            topImbal = parent;
        parent = parent->m_leftSubtree;
    }
    // Insert the subtree supplied.
    nodeSetLeftChild(parent, child);
    return topImbal;
}

/*-------------------------------------------------------------------------------------
	Function		: nodeInsertRightmost
	In Parameters	: tBalTreeNode* parent - parent node
                      tBalTreeNode* child - child node
	Out Parameters	: tBalTree::tBalTreeNode* - node
	Purpose			: Insert the "child" subtree as the rightmost node of the "parent" subtree,
					  and return the topmost node that is out of balance.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline tBalTree::tBalTreeNode* tBalTree::nodeInsertRightmost(tBalTreeNode* parent, tBalTreeNode* child)
{
    ASSERT(parent);
    ASSERT(child);
    tBalTreeNode* topImbal = 0;
    long childCount = nodeGetCount(child);
    // Move to rightmost node, updating balance on the way.
    while (parent->m_rightSubtree)
    {
        parent->m_rightNodeCount += childCount;
        if (!topImbal && nodeNeedsBalance(parent))
            topImbal = parent;
        parent = parent->m_rightSubtree;
    }
    // Insert the subtree supplied.
    nodeSetRightChild(parent, child);
    return topImbal;
}


/*-------------------------------------------------------------------------------------
	Function		: nodeMakeBalancePoint
	In Parameters	: tBalTreeNode* oldRoot - old root
  	Out Parameters	: tBalTree::tBalTreeNode* - new balanced root
	Purpose			: Given the root of a subtree, determine the subtree's correct balance point
					  and make it the new subtree root; return the new subtree root.  Tracking
					  imbalance is unnecessary here since this routine is only called during
					  a rebalance operation.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline tBalTree::tBalTreeNode* tBalTree::nodeMakeBalancePoint(tBalTreeNode* oldRoot)
{
    ASSERT(oldRoot);
    tBalTreeNode* root = oldRoot;
    long nodes = nodeGetCount(oldRoot);
    long pos = nodeGetBalanceItem(nodes);
    if (nodes > 2 && root->m_leftNodeCount != pos)  // root shift required
    {
        root = nodeFindItem(oldRoot, pos);
        // Cut the link between the new root and its parent, noting 
        // whether the new root's parent is on its left or right.
        tBalTreeNode* parent = root->m_parent;
        ASSERT(parent);             // should always be nonzero
        int leftOfRoot;             // new root's PARENT is on its left
        leftOfRoot = parent->m_rightSubtree == root ? 1 : 0;
        if (leftOfRoot)
            nodeSetRightChild(parent, 0);   // note: does not affect old child
        else
            nodeSetLeftChild(parent, 0);
        // Update node counts back to the old root, moving any
        // subtrees that are out of place.
        tBalTreeNode* prev;
        tBalTreeNode* cur = root;
        while (cur != oldRoot)
        {
            prev = cur;
            cur = parent;
            ASSERT(cur);
            parent = cur->m_parent;
            if (cur->m_leftSubtree == prev)     // cur is right of root
            {
                if (leftOfRoot)     // prev left of root, cur right of root
                {
                    nodeInsertLeftmost(root, cur->m_leftSubtree);
                    nodeSetLeftChild(cur, 0);
                    leftOfRoot = 0;
                }
                else
                    nodeSetLeftChild(cur, cur->m_leftSubtree);  // update counts
            }
            else if (cur->m_rightSubtree == prev)   // cur is left of root
            {
                if (!leftOfRoot)    // prev right of root, cur left of root
                {
                    nodeInsertRightmost(root, cur->m_rightSubtree);
                    nodeSetRightChild(cur, 0);
                    leftOfRoot = 1;
                }
                else
                    nodeSetRightChild(cur, cur->m_rightSubtree);    // counts
            }
        }
        // Insert the remaining old root subtree under the new root.
        if (root != oldRoot)
        {
            if (leftOfRoot)
                nodeInsertLeftmost(root, oldRoot);
            else
                nodeInsertRightmost(root, oldRoot);
        }
    }
    root->m_parent = 0;
    return root;
}

/*-------------------------------------------------------------------------------------
	Function		: remove
	In Parameters	: POSITION& node - position of node
  	Out Parameters	: 
	Purpose			: Removes the specified node from the tree, invalidates the
					  POSITION passed.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline void tBalTree::remove(POSITION& node)
{
    if (node)
    {
        nodeRemove((tBalTreeNode*)node);
        node = 0;
    }
}

/*-------------------------------------------------------------------------------------
	Function		: GetItem
	In Parameters	: long - item number
  	Out Parameters	: POSITION - position
	Purpose			: Returns a POSITION value for the specified 0-based item.  The result is
					  0 if the item is not found.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline POSITION tBalTree::GetItem(long item)
{
    POSITION found = 0;
    if (m_root && item >= 0 && item < nodeGetCount(m_root))
        found = (POSITION)nodeFindItem(m_root, item);
    return found;
}

/*-------------------------------------------------------------------------------------
	Function		: find
	In Parameters	: void* key - key
  	Out Parameters	: POSITION - position
	Purpose			: Returns a POSITION value for the specified item.  The result is
					  0 if the item is not found.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline POSITION tBalTree::find(void* key)
{
    POSITION found = 0;
    relativeKeyValue where;
    tBalTreeNode* cur = m_root;
    while (cur && !found)
    {
        where = onCompareKeys(key, cur->m_nodeKey);
        if (where == less)
            cur = cur->m_leftSubtree;
        else if (where == greater)
            cur = cur->m_rightSubtree;
        else
            found = (POSITION)cur;
    }
    return found;
}

/*-------------------------------------------------------------------------------------
	Function		: getKey
	In Parameters	: POSITION node - position
  	Out Parameters	: void *- node pointer
	Purpose			: Returns the specified item's key pointer.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline void* tBalTree::getKey(POSITION node)
{
    return node ? ((tBalTreeNode*)node)->m_nodeKey : 0;
}

/*-------------------------------------------------------------------------------------
	Function		: getData
	In Parameters	: POSITION node - position
  	Out Parameters	: void *- node pointer
	Purpose			: Returns the specified item's data pointer.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline void* tBalTree::getData(POSITION node)
{
    STAT_UPDATE(m_nGet);
    return node ? ((tBalTreeNode*)node)->m_nodeData : 0;
}

/*-------------------------------------------------------------------------------------
	Function		: setData
	In Parameters	: POSITION node - position
					  void * data - data
  	Out Parameters	: int - 1 :successful / not
	Purpose			: Sets the specified item's data pointer.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline int tBalTree::setData(POSITION node, void* data)
{
    ASSERT(node);
    if (!node)
        return 0;
    STAT_UPDATE(m_nSet);
    if (((tBalTreeNode*)node)->m_nodeData)
        onDeleteData(((tBalTreeNode*)node)->m_nodeData);
    return onSetData(((tBalTreeNode*)node)->m_nodeData, data);
}

/*-------------------------------------------------------------------------------------
	Function		: First
	In Parameters	: 
  	Out Parameters	: POSITION - position
	Purpose			: Move to the first (leftmost) node in the tree.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline POSITION tBalTree::First(void)
{
    tBalTreeNode* cur = m_root;
    while (cur && cur->m_leftSubtree)
        cur = cur->m_leftSubtree;
    return (POSITION)cur;
}

/*-------------------------------------------------------------------------------------
	Function		: Last
	In Parameters	: 
  	Out Parameters	: POSITION - position
	Purpose			: Move to the last (rightmost) node in the tree.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline POSITION tBalTree::Last(void)
{
    tBalTreeNode* cur = m_root;
    while (cur && cur->m_rightSubtree)
        cur = cur->m_rightSubtree;
    return (POSITION)cur;
}

/*-------------------------------------------------------------------------------------
	Function		: Prev
	In Parameters	: POSITION - position
  	Out Parameters	: POSITION - previous position
	Purpose			: Move to the previous position in the tree.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline POSITION tBalTree::Prev(POSITION node)
{
    tBalTreeNode* cur = (tBalTreeNode*)node;
    if (cur)
    {
        if (cur->m_leftSubtree)
        {
            cur = cur->m_leftSubtree;
            while (cur && cur->m_rightSubtree)
                cur = cur->m_rightSubtree;
        }
        else
        {
            tBalTreeNode* prev = cur;
            cur = cur->m_parent;
            while (cur && cur->m_leftSubtree == prev)
            {
                prev = cur;
                cur = cur->m_parent;
            }
        }
    }
    return (POSITION)cur;
}

/*-------------------------------------------------------------------------------------
	Function		: Next
	In Parameters	: POSITION - position
  	Out Parameters	: POSITION - next position
	Purpose			: Move to the next position in the tree.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline POSITION tBalTree::Next(POSITION node)
{
    tBalTreeNode* cur = (tBalTreeNode*)node;
    if (cur)
    {
        if (cur->m_rightSubtree)
        {
            cur = cur->m_rightSubtree;
            while (cur && cur->m_leftSubtree)
                cur = cur->m_leftSubtree;
        }
        else
        {
            tBalTreeNode* prev = cur;
            cur = cur->m_parent;
            while (cur && cur->m_rightSubtree == prev)
            {
                prev = cur;
                cur = cur->m_parent;
            }
        }
    }
    return (POSITION)cur;
}

/*-------------------------------------------------------------------------------------
	Function		: GetItemIndex
	In Parameters	: POSITION - position
  	Out Parameters	: long - index
	Purpose			: Get the specified node's 0-based item index.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline long tBalTree::GetItemIndex(POSITION node)
{
    ASSERT(node);
    if (!node)
        return 0;
    tBalTreeNode* cur = (tBalTreeNode*)node;
    tBalTreeNode* prev = 0;
    long pos = cur->m_leftNodeCount;
    while (cur->m_parent)
    {
        prev = cur;
        cur = cur->m_parent;
        if (cur->m_rightSubtree == prev)
            pos += cur->m_leftNodeCount + 1;
    }
    return pos;
}

/*-------------------------------------------------------------------------------------
	Function		: DumpStructure
	In Parameters	: -
  	Out Parameters	: -
	Purpose			: Output tree structure as debug info.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline void tBalTree::DumpStructure(void)
{
    #ifdef _DEBUG
        if (m_root)
            dumpStructure(m_root, 0);
        else
            TRACE(".....empty.....\n");
    #endif
}

/*-------------------------------------------------------------------------------------
	Function		: DumpStatistics
	In Parameters	: -
  	Out Parameters	: -
	Purpose			: Output tree statistics as debug info.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline void tBalTree::DumpStatistics(void)
{
    #ifdef _DEBUG
        TRACE("Set operations   = %li\n", m_nSet);
        TRACE("Get operations   = %li\n", m_nGet);
        TRACE("Balance (auto)   = %li\n", m_nBalAuto);
        TRACE("Balance (manual) = %li\n", m_nBalManual);
    #endif
}

/*-------------------------------------------------------------------------------------
	Function		: ResetStatistics
	In Parameters	: -
  	Out Parameters	: -
	Purpose			: Reset tree statistics.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
inline void tBalTree::ResetStatistics(void)
{
    #ifdef _DEBUG
        m_nBalManual = 0;           // manually performed balance operations
        m_nBalAuto = 0;             // autobalance operations
        m_nGet = 0;                 // number of data retrieval operations
        m_nSet = 0;                 // number of data storage operations
    #endif
}

#endif
#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning (default:6011)
#endif