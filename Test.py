from uuid import uuid4
import Tree
from colorama import Fore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class TestUser(Tree.User) : 
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
            isSessionKey = bool.from_bytes(clear[0:])
            newKeyId = int.from_bytes(clear[1:9])
            newKey = clear[9:]
        except InvalidTag : 
            print(f"Invalid decrypt for {self.userID}")
            return
        print(f"{self.userID} received group key {newKeyId}")
        self.keys[newKeyId] = newKey
        if isSessionKey : 
            self.sessionKey=newKeyId
    
    def __repr__(self) -> str:
        liste = []
        for keyId in self.keys :
            if keyId == self.sessionKey : 
                liste.append(f"{Fore.LIGHTRED_EX}{keyId}:{self.keys[keyId].hex()}{Fore.WHITE}")
            else : 
                liste.append(f"{keyId}:{self.keys[keyId].hex()}")
        return f"TestUser [{Fore.GREEN + self.userID + Fore.WHITE}] keys : \n - {"\n - ".join(liste)}"
    @staticmethod
    def sendGroup(data:bytes) -> None : 
        
        for i in TestUser.instances : 
            i.receiveGroup(data)


if __name__ == "__main__" : 
    
    test = Tree.LKH(TestUser.sendGroup,debug=True)
    Users = [TestUser() for i in range(5)]
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
    print(Users)