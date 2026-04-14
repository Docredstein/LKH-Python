import cryptography
import os
import math
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from collections.abc import Callable
from uuid import uuid4
from colorama import Fore,init
from random import randint
from copy import copy
import matplotlib.pyplot as plt
from matplotlib.axes import Axes
init()


class Packet() :
    def toBytes(self) :
        pass
    @staticmethod
    def fromBytes():
        pass
    
class KeyUpdatePacket(Packet) : 
    def __init__(self,newKey:bytes,newKeyid:int,isSessionKey:bool,deleteNewKey:bool) -> None:
        super().__init__()
        self.newKey = newKey
        self.newKeyid = newKeyid
        self.isSessionKey = isSessionKey
        self.deleteNewKey = deleteNewKey
    
    def toBytes(self) -> bytes:
        flags = int(self.isSessionKey) | (int(self.deleteNewKey)<<1)
        return flags.to_bytes()+self.newKeyid.to_bytes(8)+self.newKey
    @staticmethod
    def fromBytes(data:bytes) -> KeyUpdatePacket:
        flags = data[0]
        isSessionKey = bool(flags & 1)
        deleteNewKey = bool((flags>>1) & 1)
        newKeyId = int.from_bytes(data[1:9])
        newKey = data[9:]
        return KeyUpdatePacket(newKey,newKeyId,isSessionKey,deleteNewKey)




class UnsupportedAlgorithm(Exception) : 
    pass

class User: 
    def __init__(self,userID:str,send:Callable[[bytes],None]) -> None:
        self.userID = userID
        self.send = send
    def __repr__(self) -> str:
        return f"{self.userID}"
class Node : 
    def __init__(self,id,left:Node|None=None,right:Node|None=None,parent:Node|None=None, key:bytes=b"",keyid:int=0,user:User|None = None,depth:int = 0) -> None:
        self.left:Node | None = left    
        self.right:Node | None = right
        self.parent:Node | None = parent
        self.key: bytes = key
        self.id = id
        self.user =user
        self.keyid = keyid
        self.depth = depth
    def __copy__(self) : 
        return Node(self.id,self.left,self.right,self.parent,self.key,self.keyid,self.user)
    def isInternal(self) -> bool : 
        return self.left is not None or self.right is not None
    def fixIndex(self) : 
        
        if self.right is not None : 
            self.right.id = self.id*2 +1
            self.right.depth = self.depth+1
            self.right.fixIndex()
        if self.left is not None : 
            self.left.id = self.id*2 
            self.left.depth = self.depth+1
            self.left.fixIndex()
    def __repr__(self,prefix="") -> str:
        return f"{prefix}|Node {self.id} {self.keyid} [{Fore.YELLOW}{self.key.hex()}{Fore.RESET}] : {self.user.userID if self.user is not None else "None"}" + ("" if self.left is None else f"\n{self.left.__repr__(prefix+"\t")}") + ("" if self.right is None else f"\n{self.right.__repr__(prefix+"\t")}") 
class LKH : 
    numberOfKey = 0
    def __init__(self,sendGroup:Callable[[bytes],None],debug=False) -> None:
        self.root:Node = Node(1)
        self.debug = debug
        #self.numberOfReceiver:int =0
        self.algorithm = "AES256-GCM"
        self.sendGroup = sendGroup

        
        self.usedKeyId:dict[int,bool] = {}
        #self.depth:dict[int,list[Node]] = {}
        self.depth:dict[int,set[int]] = {} #Association Couche -> keyId
        self.users:dict[str,Node] = {}
        self.nodes: dict[int,Node] = {} #Association Keyid -> Node
        self.root.key = self.generateKey()
        self.root.keyid = self.generateKeyId()
    
    
    def updateKey(self,node:Node,nodesToDelete:list[Node]=[]) :
        """
        Mets à jours la clé de node jusqu'à root
        """
        print(f"Starting Update on node {node}")
        for i in nodesToDelete :
            if self.debug : 
                print(f"Deleting key {i.keyid}")
            updatePacket = KeyUpdatePacket(newKey=i.key,newKeyid=i.keyid,isSessionKey=False,deleteNewKey=True).toBytes()
            self.encrypt(key=self.root.key,data=updatePacket,aad=self.root.keyid.to_bytes(8))
            self.sendGroup(updatePacket)
        
        path = {}
        current:None|Node = node
        lastOne:None|Node = None # Est-ce le noeud feuille duquel on part ?
        while current is not None : 
            
            oldKey = current.key
            
            current.key = self.generateKey()
            if self.debug:
                print(f"[Node  : {current.id}][{current.keyid}]Old : {oldKey.hex()} New : {current.key.hex()}")
            path[current.keyid] = current.key
            if lastOne != None: 
                print("-------------------------------------------")
                print(current)
                print(current.parent)
                print(current.right)
                print(current.left)
                assert current.left is not None 
                assert current.right is not None 
                packetData = KeyUpdatePacket(newKey=current.key,newKeyid=current.keyid,isSessionKey=(current==self.root),deleteNewKey=False)
                packet = self.encrypt(key=current.left.key,data=packetData.toBytes(),aad=current.left.keyid.to_bytes(8))
                
                if self.debug : 
                    print(f"Sending keys {current.keyid} to node {current.left.id}: {packet.hex()}")
                self.sendGroup(packet)
                
                packet = self.encrypt(key=current.right.key,data=packetData.toBytes(),aad=current.right.keyid.to_bytes(8))
                
                if self.debug : 
                    print(f"Sending keys {current.keyid} to node {current.right.id}: {packet.hex()}")
                self.sendGroup(packet)
             
                
            lastOne = current    
            current = current.parent
        if node.user is not None :
            for i in path : 
                if self.debug :
                    print(f"Private send of key {i}")
                node.user.send((i==self.root.keyid).to_bytes()+i.to_bytes(8)+path[i])

            
                
    def encrypt(self,key:bytes,data:bytes,aad:bytes) -> bytes :
        match self.algorithm :
            case "AES256-GCM" : 
                aesgcm = AESGCM(key)
                nonce = os.urandom(12)
                ct = aesgcm.encrypt(nonce,data,aad)
                return aad + nonce+ct
            case _ :
                raise UnsupportedAlgorithm
        
    def generateKey(self) -> bytes : 
        match self.algorithm : 
            case "AES256-GCM" : 
                return AESGCM.generate_key(256)
            case _ : 
                raise UnsupportedAlgorithm
            

        
    def splitNode(self,nodeToSplit:Node,userToAdd:User):
        """
        Sépare la nodeToSplit en ajoutant la nodeToAdd et en descendant son utilisateur
        """
        
        right= Node(2*nodeToSplit.id+1,user=userToAdd,keyid=self.generateKeyId())
        
        self.users[userToAdd.userID] = right
        right.parent = nodeToSplit
        parentDepth = nodeToSplit.depth
        left = copy(nodeToSplit)
        print(self.depth)
        self.depth[parentDepth].remove(nodeToSplit.keyid)
        left.id = nodeToSplit.id * 2    
        nodeToSplit.user = None 
        
        left.parent = nodeToSplit
        
        
        nodeToSplit.right = right
        nodeToSplit.left = left
        nodeToSplit.keyid = self.generateKeyId()
        
        self.nodes[right.keyid] = right
        self.nodes[left.keyid] = left
        self.nodes[nodeToSplit.keyid] = nodeToSplit
        
        assert left.user is not None
        
        self.users[left.user.userID] = left
        self.users[userToAdd.userID] = right
        #parentDepth = math.floor(math.log2(nodeToSplit.id))
        
        #self.depth[parentDepth].pop(self.depth[parentDepth].index(nodeToSplit))
        
        left.depth = parentDepth+1
        right.depth = parentDepth+1
        if parentDepth+1 in self.depth : 
            self.depth[parentDepth+1].add(left.keyid)
            self.depth[parentDepth+1].add(right.keyid)
        else :
            self.depth[parentDepth+1] = set([left.keyid,right.keyid])
        if self.debug :
            print(f"Before update topo : {self}")
        self.updateKey(right)
    
    def fixDepthDict(self,node:Node,initialDepth:int) :
        if node.user is not None : 
            #self.depth[node.depth].pop(self.depth[node.depth].index(node))
            self.depth[node.depth].remove(node.keyid)
            node.depth = initialDepth
            if node.depth in self.depth : 
                self.depth[node.depth].add(node.keyid)
            else : 
                self.depth[node.depth] = set([node.keyid])
        else : 
            assert node.left is not None
            self.fixDepthDict(node.left,initialDepth=initialDepth+1)
            assert node.right is not None 
            self.fixDepthDict(node.right,initialDepth+1)
     
    def mergeNode(self,nodeToBeDeleted:Node) : 
        parent = nodeToBeDeleted.parent    
        if parent is None : 
            raise Exception("Unable to merge node, no parent")
        otherNode = parent.left if parent.right == nodeToBeDeleted else parent.right
        assert otherNode is not None
        #parentDepth =  math.floor(math.log2(parent.id))
        parentDepth = parent.depth
        #self.depth[parentDepth+1].pop(self.depth[parentDepth+1].index(otherNode))
        #self.depth[parentDepth+1].pop(self.depth[parentDepth+1].index(nodeToBeDeleted))
        """C'est incorrect, il est possible qu'un utilisateurs partent et que son frère ne soit pas une feuille et donc pas dans self.depth"""
        #if (otherNode in self.depth[parentDepth+1]) : 
        #    self.depth[parentDepth+1].pop(self.depth[parentDepth+1].index(otherNode))
        
        #self.depth[parentDepth+1].pop(self.depth[parentDepth+1].index(nodeToBeDeleted))
        print(parentDepth)
        print(self.depth)
        self.depth[parentDepth+1].remove(nodeToBeDeleted.keyid)
        


        
            
        parent.keyid = otherNode.keyid
        parent.key = otherNode.key
        parent.left = otherNode.left
        parent.right = otherNode.right 
        parent.user = otherNode.user
        
        self.nodes[parent.keyid] = parent
        del self.nodes[nodeToBeDeleted.keyid]
        if len(self.depth[parentDepth])<=0 :
            self.depth[parentDepth] = set([parent.keyid])
        else : 
            self.depth[parentDepth].add(parent.keyid)
        self.fixDepthDict(parent,parentDepth)
        # C'est vraiment pas idéal mais je ne suis pas sûr de comment faire mieux 
        
        if parent.left is not None : 
            parent.left.parent = parent 
        if parent.right is not None : 
            parent.right.parent = parent
        
        # assert parent.user is not None
        # C'est incorrect, il est possible que othernode ne soit pas une feuille
        if parent.user is not None:
            self.users[parent.user.userID] = parent
        parent.fixIndex()
        if self.debug:
            print(f"After Update : \n{self}")
            #print(parent.parent)
        self.updateKey(parent,nodesToDelete=[nodeToBeDeleted])
        
    

    
    def addUser(self,user:User) :
        if user in self.users : 
            raise Exception("User Already in Graph")
        if self.debug : 
            print(f"Adding user {user}") 
        if len(self.users) <=0 :
            if self.debug:
                print("First User !")
            self.root.user = user
            self.updateKey(self.root)
            self.users[user.userID] = self.root
            self.depth[0] = set([self.root.id])
            self.nodes[self.root.id] = self.root
            return 
        targetDepth = min([i for i in self.depth if len(self.depth[i])>0])
        for i in self.depth[targetDepth] : 
            
            parent = self.nodes[i]
            break
        #parent = [i for i in self.depth[targetDepth] if i.id ==nextNodeiD][0]
        
        print(f"Going to split node {parent}")
        self.splitNode(parent,user)
    
    
    def generateKeyId(self) :
        if self.debug : 
            LKH.numberOfKey+=1
            return  LKH.numberOfKey
        out = randint(0,2**(8*8)-1)
        while out in self.usedKeyId : 
             out = randint(0,2**(8*8)-1)
        return out
    
    def removeUser(self,user:User) :
        if user.userID not in self.users : 
            raise Exception(f"User {user.userID} not found in tree, available users {self.users}") 
        if self.debug : 
            print(f"{Fore.LIGHTRED_EX}Removing {Fore.RESET} User {Fore.YELLOW}{user.userID}{Fore.RESET}")
        node = self.users[user.userID]
        del self.users[user.userID]
        if node==self.root:
            self.root.user = None 
            self.depth = {}
            self.root.key = b""
            self.usedKeyId = {}
            self.nodes = {}
            return 
        
        self.mergeNode(node)
        return 
    
        
        
    def __repr__(self) -> str:
        return f"LKH Tree of {len(self.users)} recievers using {Fore.GREEN + self.algorithm + Fore.RESET}\nTree:\n{self.root}"

    
#Full ChatGPT 

def draw_tree_matplotlib(root,maxY=None,specialKeys:list[int]=[],ax:None|Axes=None):
    if ax is None :
        fig, ax = plt.subplots(figsize=(20, 10))
    else : 
        fig = ax.figure 
    ax.set_axis_off()

    def draw_node(node:Node, x, y, dx,ax):
        if node is None:
            return
        
        # Dessiner le noeud
        ax.text(x, y, f"{node.id}", ha='center', va='center',
                bbox=dict(boxstyle="circle", fc="lightblue" if node.keyid not in specialKeys else "lightcoral", ec="black"))
        ax.text(x,y-0.3,f"{node.keyid}",ha='center',va='center',fontsize=8)
        if node.user is not None : 
            ax.text(x,y-0.8,f"{node.user.userID}",ha='center',va='center',fontsize=16,c="red")
        # Enfant gauche
        if node.left:
            x_left = x - dx
            y_child = y - 1
            ax.plot([x, x_left], [y, y_child], 'k-')
            draw_node(node.left, x_left, y_child, dx / 2,ax)

        # Enfant droit
        if node.right:
            x_right = x + dx
            y_child = y - 1
            ax.plot([x, x_right], [y, y_child], 'k-')
            draw_node(node.right, x_right, y_child, dx / 2,ax)

    draw_node(root, x=0, y=0, dx=4,ax=ax)
    ax.set_xlim(-10, 10)
    if maxY is not None :
        
        ax.set_ylim(-maxY, 0.1)
    return fig