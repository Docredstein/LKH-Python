import cryptography
import os
import math
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from collections.abc import Callable
from uuid import uuid4
from colorama import Fore,init

init()
class UnsupportedAlgorithm(Exception) : 
    pass

class User: 
    def __init__(self,userID:str,send:Callable[[bytes],None]) -> None:
        self.userID = userID
        self.send = send
    def __repr__(self) -> str:
        return f"{self.userID}"
class Node : 
    def __init__(self,id,left:Node|None=None,right:Node|None=None,parent:Node|None=None, key:bytes=b"",user:User|None = None) -> None:
        self.left:Node | None = left    
        self.right:Node | None = right
        self.parent:Node | None = parent
        self.key: bytes = key
        self.id = id
        self.user =user


    def isInternal(self) -> bool : 
        return self.left is not None or self.right is not None
    def __repr__(self,prefix="") -> str:
        return f"{prefix}|Node {self.id} [{Fore.YELLOW}{self.key.hex()}{Fore.WHITE}] : {self.user}" + ("" if self.left is None else f"\n{self.left.__repr__(prefix+"\t")}") + ("" if self.right is None else f"\n{self.right.__repr__(prefix+"\t")}") 
class LKH : 
    
    def __init__(self,sendGroup:Callable[[bytes],None],debug=False) -> None:
        self.root:Node = Node(1)
        self.debug = debug
        #self.numberOfReceiver:int =0
        self.algorithm = "AES256-GCM"
        self.sendGroup = sendGroup
        self.root.key = self.generateKey()
        self.depth:dict[int,list[Node]] = {}
        self.users:dict[str,Node] = {}
        
    def updateKey(self,node:Node) :
        """
        Mets à jours la clé de node jusqu'à root
        """
        path = {}
        current:Node = node 
        while current is not None : 
            
            oldKey = current.key
            current.key = self.generateKey()
            path[current.id] = current.key
            if current.isInternal() : 
                packet = self.encrypt(oldKey,current.key,current.id.to_bytes(8))
                
                if self.debug : 
                    print(f"Sending keys {current.id}")
                self.sendGroup(packet)
            current = current.parent
        if node.user is not None :
            for i in path : 
                if self.debug :
                    print(f"Private send of key {i}")
                node.user.send(i.to_bytes(8)+path[i])
                
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
    def isSlotAvailable(self) -> bool : 
        if len(self.users)<=0:
            return False
        return  math.floor(math.log2(len(self.users)))==len(self.users )
        
    def splitNode(self,nodeToSplit:Node,userToAdd:User):
        """
        Sépare la nodeToSplit en ajoutant la nodeToAdd et en descendant son utilisateur
        """
        
        right= Node(2*nodeToSplit.id+1,user=userToAdd)
        self.users[userToAdd.userID] = right
        left = Node(2*nodeToSplit.id,user=nodeToSplit.user,key=nodeToSplit.key)  
        nodeToSplit.user = None 
        left.parent = nodeToSplit
        right.parent = nodeToSplit
        nodeToSplit.right = right
        nodeToSplit.left = left
        assert left.user is not None
        self.users[left.user.userID] = left
        self.users[userToAdd.userID] = right
        parentDepth = math.floor(math.log2(nodeToSplit.id))
        self.depth[parentDepth].pop(self.depth[parentDepth].index(nodeToSplit))
        if parentDepth+1 in self.depth : 
            self.depth[parentDepth+1].append(left)
            self.depth[parentDepth+1].append(right)
        else :
            self.depth[parentDepth+1] = [left,right]
        self.updateKey(right)
        
    def mergeNode(self) : 
        pass    
    

    
    def addUser(self,user:User) :
        if self.debug : 
            print(f"Adding user {user}") 
        if len(self.users) <=0 :
            if self.debug:
                print("First User !")
            self.root.user = user
            self.updateKey(self.root) 
            self.users[user.userID] = self.root
            self.depth[0] = [self.root]
            return 
        targetDepth = min([i for i in self.depth if len(self.depth[i])>0])
        nextNodeiD = min([i.id for i in self.depth[targetDepth]])
        parent = [i for i in self.depth[targetDepth] if i.id ==nextNodeiD][0]
        self.splitNode(parent,user)
        
    
    
    def removeUser(self) : 
        pass
    def __repr__(self) -> str:
        return f"LKH Tree of {len(self.users)} recievers using {self.algorithm}\nTree:\n{self.root}"

    
if __name__ == "__main__" : 
    UserCount = 0 
    def CreateDebugUser() : 
        global UserCount
        UserCount+=1
        String = f"User{UserCount} "
        return User(str(uuid4()),lambda x : print(String + x.hex()))
    test = LKH(lambda x : print(f"Global {x.hex()}"),debug=True)
    User1 = CreateDebugUser()
    print(test)
    test.addUser(User1)
    print(test)
    test.addUser(CreateDebugUser())
    print(test)
    