from trie import HexaryTrie
from eth_utils import keccak
from trie.utils.nodes import decode_node
from typing import List, Union, Optional
from dataclasses import dataclass, field
import rlp

# Patricia trie =
#     [ <16>, [ <>, <>, <>, <>, [ <00 6f>, [ <>, <>, <>, <>, <>, <>, [ <17>, [ <>, <>, <>, <>, <>, <>, [ <35>, 'coin' ], <>, <>, <>, <>, <>, <>, <>, <>, <>, 'puppy' ] ],
#      <>, <>, <>, <>, <>, <>, <>, <>, <>, 'verb' ] ], <>, <>, <>, [ <20 6f 72 73 65>, 'stallion' ], <>, <>, <>, <>, <>, <>, <>, <> ]
testcase1 = {'646f' : 'verb', '646f67' : 'puppy', '646f6765' : 'coin', '686f727365' : 'stallion'}

# Testcase, Root Hash = a9116924943abeddebf1c0da975ebef7b2006ede340b0f9e18504b65b52948ed
testcase2 = {'a711355' : '45'}
# Testcase, Root Hash = 39067a59d2192dbde0af0968ba50ac88d02a41e3a9e06834e6f3490edec03cb5
testcase3 = {'a711355' : '45', 'a7f9365' : '2'}
# Testcase, Root Hash = 608b7c482ee39d36c1aadbbf38d8d4d7a557dbe5d0484c02a44a8bdb3f87f1e6
testcase4 = {'a711355' : '45', 'a77d337' : '1', 'a7f9365' : '2'}    # Overlength
# Testcase: Root Hash = 5838ad5578f346f40d3e6b71f9a82ae6e5198dd39c52e18deec63734da512055
testcase5 = {'a711355' : '45', 'a77d337' : '1', 'a7f9365' : '2', 'a77d397' : '12'}
# Testcase, Root Hash = 0214f87faeb8417f4e5a73df8ee4aaaf904571fb9f859e2e8aa64f6f003ba3bf
testcase6 = {'a711355' : '45', 'a711356' : '46', 'a711357' : '47', 'a77d337' : '1', 'a7f9365' : '2', 'a77d397' : '12'}
# Testcase
testcase7 = {'7c3002ad756d76a643cb09cd45409608abb642d9' : '10', '7c303333756d555643cb09cd45409608abb642d9' : '20', '7c303333756d777643cb09c999409608abb642d9' : '30', '7c303333756d777643cb09caaa409608abb642d9' : '40', '111102ad756d76a643cb09cd45409608abb642d9' : '50'}
# Testcase
testcase8 = {'7c3002ad756d76a643cb09cd45409608abb642d9' : '8', '7c303333756d555643cb09cd45409608abb642d9' : '20', '7c303333756d777643cb09c999409608abb642d9' : '24', '7c303333756d777643cb09caaa409608abb642d9' : '42', '111102ad756d76a643cb09cd45409608abb642d9' : '50', '11113333756d76a643cb09cd45409608abb642d9' : '6'}

# Define node type
EXT_EVEN = "00"
EXT_ODD = "1"
LEAF_EVEN = "20"
LEAF_ODD = "3"

@dataclass
class Node:
    prefix: str # node的狀態
    key: bytes # node的key
    value: bytes # node的value
    hash: bytes # get hash的時候才存進來
    branch: List[Optional["Node"]] = field(default_factory=lambda: [None] * 17) # node的branch
    
    def is_extension(self):
        return self.prefix in (EXT_EVEN, EXT_ODD)
    def is_leaf(self):
        return self.prefix in (LEAF_EVEN, LEAF_ODD)
    def is_branch(self):
        return self.prefix == None

rootNode = None

# rlp encode for leaf node 
def encode_node(node):
    rlpnode = rlp.encode(node)
    if len(rlpnode) < 32: # store rlp in branch node without hashing
        return node
    rlphash = keccak(rlpnode)
    return rlphash
 
# rlp encode + hash for root node
def root_encode_node(node):
    rlpnode = rlp.encode(node)
    rlphash = keccak(rlpnode)
    return rlphash
 
def MPT_construct(testcase):
    for k, v in testcase.items():
        print("- 插入kvpair：",k,v)
        MPT_insert(k,v)
        roothash = get_root_node_hash_str(get_MPT_root_hash(rootNode))
        MPT_display(rootNode)
        print("roothash: ", get_MPT_root_hash(rootNode))
        print("roothash in str: ", roothash)

def get_prefix_type(is_leaf: bool, key: str) -> str:
    if is_leaf:
        if len(key) % 2 == 0:
            return LEAF_EVEN
        else:
            return LEAF_ODD
    else:
        if len(key) % 2 == 0:
            return EXT_EVEN
        else:
            return EXT_ODD

def get_shared_nibble(a: str, b: str) -> str:
    shared_nibble = ""
    for x, y in zip(a, b):       # 平行比對兩個字串的每個字元
        if x == y:               # 如果一樣
            shared_nibble += x          # 就加進 prefix
        else:
            break                # 不一樣就中斷
    return shared_nibble                # 回傳目前找到的共同前綴

def get_root_node_hash_str(hash) -> str:
    if type(hash) == bytes:
        roothash = hash.hex()
    else:
        hash = root_encode_node(hash)
        roothash = hash.hex()
    return roothash
    
def get_MPT_root_hash(node: Node) -> bytes:
    if node.is_leaf():
        node_hash = encode_node([node.key, node.value])
        node.hash = node_hash

        return node_hash
    if node.is_extension() or node.is_branch():
        arr = [b""] * 17
        for i in range(16):
            if node.branch[i]:
                arr[i] = get_MPT_root_hash(node.branch[i])

    branch_hash = encode_node(arr)
    if node.is_branch():
        node_hash = branch_hash
    else:
        node_hash = encode_node([node.key, branch_hash])

    node.hash = node_hash
    return node_hash

def MPT_display(node: Node, depth=0):
    indent = " " * depth
    if node.is_leaf():
        print(f"{indent}Leaf, [key]: {node.key.hex()}, [value]: {node.value}, [hash]: {node.hash}")
        return
    
    #print(node.branch)
    if node.is_extension():
        print(f"{indent}Extension, [key]: {node.key.hex()}, [hash]: {node.hash}")
        for i in range (16):
            child = node.branch[i]
            if child is not None:
                print(f"{indent}    ├─ [{i:X}]")
                MPT_display(child, depth + 2)

    if node.is_branch():
        print(f"{indent}Branch, [hash]: {node.hash}")
        for i in range (16):
            child = node.branch[i]
            if child is not None:
                print(f"{indent}    ├─ [{i:X}]")
                MPT_display(child, depth + 2)

def MPT_insert(key: str, value: str):
    global rootNode
    rootNodeUpdate = False
    # 第一筆kv直接建leaf node
    if(rootNode is None):
        prefix_key = get_prefix_type(True, key)
        rootNode = Node(prefix=prefix_key,key=bytes.fromhex(prefix_key + key), value=bytes(value, 'utf-8'), branch=[None]*17, hash=None)
        print("建立root node：", rootNode)
        return

    if(not rootNode.is_branch()):
        root_key = rootNode.key.hex()[len(rootNode.prefix):] # 只取key（把prefix去掉）
        print(root_key, key)
        if(get_shared_nibble(root_key, key) == ""): #找不到相同nibble那就要把rootnode要變成branch node
            oldNode = Node(prefix=rootNode.prefix, key=rootNode.key, value=rootNode.value, branch=rootNode.branch, hash=None)
            rootNode = Node(prefix=None, key=None, value=None, branch=[None]*17, hash=None) #rootnode變成branch
            
            oldkey = oldNode.key.hex()[len(oldNode.prefix):] # 只取key（把prefix去掉）
            branch_index = int(oldkey[0],16)
            oldkey = oldkey[1:]
            oldNode.prefix = get_prefix_type(False, oldkey)
            oldNode.key = bytes.fromhex(oldNode.prefix + oldkey)

            rootNode.branch[branch_index] = oldNode
            
            tmp_key = key
            branch_index = int(tmp_key[0], 16)
            tmp_key = tmp_key[1:]
            prefix_key = get_prefix_type(True, tmp_key)
            rootNode.branch[branch_index] = Node(prefix=prefix_key, key=bytes.fromhex(prefix_key + tmp_key), value=bytes(value, 'utf-8'), branch=[None]*17, hash=None)
            return

    currentNode = rootNode
    tmp_key = key

    if(rootNode.is_branch()):
        if rootNode.branch[int(key[0],16)] is not None:
            currentNode = rootNode.branch[int(key[0],16)]
            tmp_key = key[1:]

    branch_index = -1
    splitExtNode = False

    ## 找到leaf node插入點
    while not currentNode.is_leaf():
        #找相同的nibble後，取split point，並透過branch找到下一個Node
        previousNode = currentNode
        previous_tmp_key = tmp_key

        cur_key = currentNode.key.hex()[len(currentNode.prefix):] # 只取key（把prefix去掉）
        shared_nibble = get_shared_nibble(cur_key, tmp_key)
        print("(loop)欲比較的key: ", cur_key, "目前的key", tmp_key, "找到相同nibble: ", shared_nibble)
        split_pos = len(shared_nibble)
        print("split_pos:", split_pos)
        branch_index = int(tmp_key[split_pos], 16)
        print("切割位置第幾個: ", split_pos, "branch index為: ", branch_index)

        tmp_key = tmp_key[split_pos+1:]
        print("key後半部: ", tmp_key)

        #帶著key_end往下找
        if(not currentNode.branch[branch_index]): # 如果branch是空的，直接建立leaf node
            prefix_key = get_prefix_type(True, tmp_key)
            currentNode.branch[branch_index] = Node(prefix=prefix_key, key=bytes.fromhex(prefix_key + tmp_key), value=bytes(value, 'utf-8'), branch=[None]*17, hash=None)
            return
        else: 
            next_cur_key = currentNode.branch[branch_index].key.hex()[len(currentNode.prefix):]
            next_shared_nibble = get_shared_nibble(next_cur_key, tmp_key)
            if(next_shared_nibble == ""):
                print("比對下一個key: ", next_cur_key, "目前的key", tmp_key, "找到相同nibble: ", next_shared_nibble)
                tmp_key = previous_tmp_key
                print("還原tmp_key: ", tmp_key)
                splitExtNode = True
                break # 不進到下一個Node
            currentNode = currentNode.branch[branch_index] # 如果branch不是空的，往下找下一個Node

    ## 找到插入點
    ori_value = currentNode.value #暫存原本leaf node的value
    print("curNode", currentNode)
    # 找分岔點插入原本leaf node以及新的leaf node
    cur_key = currentNode.key.hex()[len(currentNode.prefix):] # 只取key（把prefix去掉）
    shared_nibble = get_shared_nibble(cur_key, tmp_key)
    print("欲比較的key: ", cur_key, "目前的key", tmp_key, "找到相同nibble: ", shared_nibble)
    if(shared_nibble == ""):
        print("errorerrorerrorerrorerrorerrorerrorerrorerrorerrorerrorerrorerrorerrorerrorerrorerrorerrorerror")

    split_pos = len(shared_nibble)
    # 換算成branch node插入點
    
    tmp_key_branch_index = int(tmp_key[split_pos], 16)
    cur_key_branch_index = int(cur_key[split_pos], 16)
    end_tmp_key = tmp_key[split_pos+1:]
    end_cur_key = cur_key[split_pos+1:]
    
    print("切割位置第幾個: ", split_pos, "兩個branch index為: ", tmp_key_branch_index, cur_key_branch_index)

    if splitExtNode:
        print("split發生在extension node")
        #前一個node要裝在新的ext node的底下
        previousNode = Node(prefix=currentNode.prefix, key=currentNode.key, value=currentNode.value, branch=currentNode.branch, hash=None)
        prefix = get_prefix_type(False, end_cur_key)
        previousNode.prefix = prefix
        previousNode.key = bytes.fromhex(prefix + end_cur_key)

        # 新建立一個extension node
        prefix = get_prefix_type(False, shared_nibble)
        print("新建extension node: prefix: ", prefix, ", shared_nibble: ", shared_nibble)
        
        currentNode.prefix = prefix
        currentNode.key = bytes.fromhex(prefix + shared_nibble)
        currentNode.value = None
        currentNode.branch = [None]*17

        prefix = get_prefix_type(True, end_tmp_key)
        currentNode.branch[tmp_key_branch_index] = Node(prefix=prefix, key=bytes.fromhex(prefix + end_tmp_key), value=bytes(value, 'utf-8'), branch=[None]*17, hash=None)
        currentNode.branch[cur_key_branch_index] = Node(prefix=previousNode.prefix, key=previousNode.key, value=previousNode.value, branch=previousNode.branch, hash=None)

    else: 
        # 新建立一個extension node
        prefix = get_prefix_type(False, shared_nibble)
        print("新建extension node: prefix: ", prefix, ", shared_nibble: ", shared_nibble)

        currentNode.prefix = prefix
        currentNode.key = bytes.fromhex(prefix + shared_nibble)
        currentNode.value = None
        currentNode.branch = [None]*17

        # 將leaf node放進extension node
        print ("新建2個leaf node: ", end_tmp_key, end_cur_key)
        tmp_arr=[b""]*17

        prefix = get_prefix_type(True, end_tmp_key)
        currentNode.branch[tmp_key_branch_index] = Node(prefix=prefix, key=bytes.fromhex(prefix + end_tmp_key), value=bytes(value, 'utf-8'), branch=[None]*17, hash=None)

        prefix = get_prefix_type(True, end_cur_key)
        currentNode.branch[cur_key_branch_index] = Node(prefix=prefix, key=bytes.fromhex(prefix + end_cur_key), value=ori_value, branch=[None]*17, hash=None)

def main():    
    MPT_construct(testcase7)


if __name__ == "__main__":
    main()