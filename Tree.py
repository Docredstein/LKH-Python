import cryptography
import os
import math
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from collections.abc import Callable
class UnsupportedAlgorithm(Exception) : 
    pass
class User: 
    def __init__(self) -> None:
        pass
class Node : 
    def __init__(self,id,left:Node|None=None,right:Node|None=None,key:bytes=b"") -> None:
        self.left:Node | None = left    
        self.right:Node | None = None
        self.key: bytes = b""
        self.id = id
    def updateKey(self,key:bytes) -> None:
        self.key = key 
    def isInternal(self) -> bool : 
        return self.left is not None or self.right is not None
    def __repr__(self,prefix="") -> str:
        return f"{prefix}|Node [{self.key}] {self.id}" + ("" if self.left is None else f"\n{self.left.__repr__(prefix+"\t")}") + ("" if self.right is None else f"\n{self.right.__repr__(prefix+"\t")}") 
class LKH : 
    
    def __init__(self,sendGroup:Callable[[bytes],None]) -> None:
        self.root:Node = Node(1)
        self.numberOfReceiver:int =0
        self.algorithm = "AES256-GCM"
        self.sendGroup = sendGroup
        self.root.updateKey(self.generateKey())
        
        
    def generateKey(self) -> bytes : 
        match self.algorithm : 
            case "AES256-GCM" : 
                return AESGCM.generate_key(256)
            case _ : 
                raise UnsupportedAlgorithm()
    def isSlotAvailable(self) -> bool : 
        if self.numberOfReceiver<=0:
            return False
        return  math.floor(math.log2(self.numberOfReceiver))==self.numberOfReceiver 
        
    def splitNode(self,node:Node) -> bytes:
        
        left = Node(2*node.id)
        right = Node(2*node.id+1) 
        left.updateKey(self.generateKey())
        right.updateKey(self.generateKey())
        self.root.updateKey(self.generateKey())
        node.left = left 
        node.right = right 
        node.updateKey(self.generateKey())
        
        
    def removeUser(self) : 
        pass
    def __repr__(self) -> str:
        return f"LKH Tree of {self.numberOfReceiver} recievers using {self.algorithm}\nTree:\n{self.root}"
    
if __name__ == "__main__" : 
    test = LKH()
    test.root.left= Node(1)
    test.root.right= Node(2)
    test.root.right.right = Node(3)
    test.root.right.left = Node(4)
    test.root.left.left = Node(5)
    print(test)
    print(test.isSlotAvailable())