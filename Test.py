from uuid import uuid4
import Tree
from colorama import Fore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import matplotlib.pyplot as plt
class TestUser(Tree.User) :
    changedKeys = set() 
    instances:list[TestUser] = []
    totalCount = 1
    def __init__(self) -> None:
        super().__init__(userID=str(TestUser.totalCount), send=self.receive)
        TestUser.totalCount+=1
        TestUser.instances.append(self)
        self.keys:dict[int,bytes] = {}
        self.sessionKey:int = 0
    def receive(self,data:bytes) -> None :
        isSessionKey = bool.from_bytes(data[:1])
        keyId = int.from_bytes(data[1:9])
        key = data[9:]
        self.keys[keyId] = key
        if isSessionKey : 
            self.sessionKey = keyId
    def receiveGroup(self,data:bytes) -> None : 
        #print(f"ReceiveGroup called for {self.userID} with {data.hex()}")
        rawkeyId = data[:8]
        keyId = int.from_bytes(rawkeyId)
        nonce = data[8:20]
        ct = data[20:]
        if keyId not in self.keys :
            print(f"no {keyId} for {self.userID} only got {self.keys.keys()}")
            return 
        key = self.keys[keyId] 
        aesgcm = AESGCM(key)
        try : 
            clear = aesgcm.decrypt(nonce=nonce,data=ct,associated_data=rawkeyId)
            UpdatePacket = Tree.KeyUpdatePacket.fromBytes(clear)
        except InvalidTag as e: 
            print(f"Invalid decrypt for {self.userID} {e}")
            return
        print(f"{self.userID} received group key {UpdatePacket.newKeyid}")
        self.keys[UpdatePacket.newKeyid] = UpdatePacket.newKey
        TestUser.changedKeys.add(UpdatePacket.newKeyid)
        if UpdatePacket.isSessionKey : 
            self.sessionKey=UpdatePacket.newKeyid
        if UpdatePacket.deleteNewKey : 
            del self.keys[UpdatePacket.newKeyid]
    
    def __repr__(self) -> str:
        liste = []
        for keyId in self.keys :
            if keyId == self.sessionKey : 
                liste.append(f"{Fore.LIGHTRED_EX}{keyId}:{self.keys[keyId].hex()}{Fore.RESET}")
            else : 
                liste.append(f"{keyId}:{self.keys[keyId].hex()}")
        return f"TestUser [{Fore.GREEN + self.userID + Fore.RESET}] keys : \n - {"\n - ".join(liste)}"
    @staticmethod
    def sendGroup(data:bytes) -> None : 
        
        for i in TestUser.instances : 
            i.receiveGroup(data)


def test_Add() : 
    test = Tree.LKH(TestUser.sendGroup,debug=True)
    Users = [TestUser() for i in range(5)]
    printUsers = lambda : print("\n".join([str(i) for i in Users]))
    print(test)
    test.addUser(Users[0])
    print(Users[0])
    print(test)
    print("++++++++++++")
    test.addUser(Users[1])
    print(Users[0])
    print(Users[1])   
    print(test)
    print("++++++++++")
    test.addUser(Users[2])
    print(test)
    print(Users[0])
    print(Users[1])
    print(Users[2])
    test.addUser(Users[3])
    print(test)
    test.addUser(Users[4])
    print(test)
    printUsers()
def test_del() : 
    test = Tree.LKH(TestUser.sendGroup,debug=True)
    Users = [TestUser() for i in range(5)]
    
    printUsers = lambda : print("\n".join([str(i) for i in Users]))
    test.addUser(Users[0])
    test.addUser(Users[1])
    test.addUser(Users[2])
    
    print(test)
    test.removeUser(Users[2])
    print(test)
    printUsers()
    test.addUser(Users[2])
    print(test)
    printUsers()
    Tree.draw_tree_matplotlib(test.root)
    plt.show()
    
def show_draw(): 
    test = Tree.LKH(TestUser.sendGroup,debug=True)
    Users = [TestUser() for i in range(32)]
    
    for i in Users : 
        test.addUser(i)
        keyids = list(TestUser.changedKeys)
        TestUser.changedKeys= set()
        fig = Tree.draw_tree_matplotlib(test.root,maxY=5,specialKeys=keyids)
        fig.savefig(f"./images/tree_{i.userID}.svg",dpi=200)
        
if __name__ == "__main__" : 
    
    
    
    
    #test_Add()
    #test_del()
    show_draw()
    pass
    