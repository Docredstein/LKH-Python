from uuid import uuid4
import Tree
from colorama import Fore

class TestUser(Tree.User) : 
    def __init__(self) -> None:
        super().__init__(userID=str(uuid4), send=self.receive)
    
    def receive(self,data:bytes) -> None :
        pass
    
    def __repr__(self) -> str:
        return f"TestUser [{Fore.GREEN + self.userID + Fore.WHITE}]"
    


if __name__ == "__main__" : 
    
    test = Tree.LKH(lambda x : print(f"Global {x.hex()}"),debug=True)
    User1 = TestUser()
    print(test)
    test.addUser(User1)
    print(test)
    test.addUser(TestUser())
    print(test)
    test.addUser(TestUser())
    print(test)