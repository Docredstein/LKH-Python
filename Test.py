from uuid import uuid4
import Tree
from colorama import Fore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import matplotlib.pyplot as plt
import random
from tqdm import tqdm
import traceback


class TestUser(Tree.User):
    changedKeys = set()
    instances: list[TestUser] = []
    totalCount = 1
    numberOfMulticast = 0
    numberOfUnicast = 0
    realist = True  # Si vrai, décode réellement les paquets reçus

    def __init__(self) -> None:
        super().__init__(userID=str(TestUser.totalCount), send=self.receive)
        TestUser.totalCount += 1
        TestUser.instances.append(self)
        self.keys: dict[int, bytes] = {}
        self.sessionKey: int = 0

    def receive(self, data: bytes) -> None:
        TestUser.numberOfUnicast += 1
        if TestUser.realist:
            isSessionKey = bool.from_bytes(data[:1])
            keyId = int.from_bytes(data[1:9])
            key = data[9:]
            self.keys[keyId] = key
            if isSessionKey:
                self.sessionKey = keyId

    def receiveGroup(self, data: bytes) -> None:
        # print(f"ReceiveGroup called for {self.userID} with {data.hex()}")
        rawkeyId = data[:8]
        keyId = int.from_bytes(rawkeyId)
        nonce = data[8:20]
        ct = data[20:]
        if keyId not in self.keys:
            # print(f"no {keyId} for {self.userID} only got {self.keys.keys()}")
            return
        key = self.keys[keyId]
        aesgcm = AESGCM(key)
        try:
            clear = aesgcm.decrypt(nonce=nonce, data=ct, associated_data=rawkeyId)
            UpdatePacket = Tree.KeyUpdatePacket.fromBytes(clear)
        except InvalidTag as e:
            # print(f"Invalid decrypt for {self.userID} {e}")
            return
        # print(f"{self.userID} received group key {UpdatePacket.newKeyid}")
        self.keys[UpdatePacket.newKeyid] = UpdatePacket.newKey
        TestUser.changedKeys.add(UpdatePacket.newKeyid)
        if UpdatePacket.isSessionKey:
            self.sessionKey = UpdatePacket.newKeyid
        if UpdatePacket.deleteNewKey:
            del self.keys[UpdatePacket.newKeyid]

    def __repr__(self) -> str:
        liste = []
        for keyId in self.keys:
            if keyId == self.sessionKey:
                liste.append(
                    f"{Fore.LIGHTRED_EX}{keyId}:{self.keys[keyId].hex()}{Fore.RESET}"
                )
            else:
                liste.append(f"{keyId}:{self.keys[keyId].hex()}")
        return f"TestUser [{Fore.GREEN + self.userID + Fore.RESET}] keys : \n - {"\n - ".join(liste)}"

    @staticmethod
    def sendGroup(data: bytes) -> None:
        TestUser.numberOfMulticast += 1
        if TestUser.realist:
            for i in TestUser.instances:
                i.receiveGroup(data)

    @staticmethod
    def reset():
        TestUser.changedKeys = set()
        TestUser.numberOfMulticast = 0
        TestUser.numberOfUnicast = 0

    @staticmethod
    def getStats():
        return {
            "keys": TestUser.changedKeys,
            "multicast": TestUser.numberOfMulticast,
            "unicast": TestUser.numberOfUnicast,
        }


def test_Add():
    test = Tree.LKH(TestUser.sendGroup, debug=True)
    Users = [TestUser() for i in range(5)]
    printUsers = lambda: print("\n".join([str(i) for i in Users]))
    print(test)
    test.addUser(Users[0])
    print(Users[0])
    print(test)
    print(test.depth)
    input("")
    print("++++++++++++")

    test.addUser(Users[1])
    print(Users[0])
    print(Users[1])
    print(test)
    print(test.depth)
    input("")
    print("++++++++++")
    test.addUser(Users[2])
    print(test)
    print(Users[0])
    print(Users[1])
    print(Users[2])
    print(test.depth)
    input("")
    test.addUser(Users[3])
    print(test)
    print(test.depth)
    input("")
    test.addUser(Users[4])
    print(test)
    printUsers()


def test_del():
    test = Tree.LKH(TestUser.sendGroup, debug=True)
    Users = [TestUser() for i in range(5)]

    printUsers = lambda: print("\n".join([str(i) for i in Users]))
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
    test = Tree.LKH(TestUser.sendGroup, debug=True)
    Users = [TestUser() for i in range(32)]

    for i in Users:
        test.addUser(i)
        stats = TestUser.getStats()
        TestUser.reset()
        fig = Tree.draw_tree_matplotlib(test.root, maxY=7, specialKeys=stats["keys"])

        fig.savefig(f"./images/tree_A{int(i.userID):02d}.svg", dpi=200)
        fig.clear()

    for i in Users:
        print(test.depth)
        input("")
        if i.userID == "18":

            a = 1
        test.removeUser(i)
        stats = TestUser.getStats()
        TestUser.reset()
        fig = Tree.draw_tree_matplotlib(test.root, maxY=7, specialKeys=stats["keys"])
        fig.savefig(f"./images/tree_R{int(i.userID):02d}.svg", dpi=200)
        fig.clear()
        print(test.depth)


def show_Worst_Case_remove():
    test = Tree.LKH(TestUser.sendGroup, debug=True)
    Users = [TestUser() for i in range(4)]
    for i in Users:
        test.addUser(i)
    fig = Tree.draw_tree_matplotlib(test.root, maxY=7)
    fig.savefig(f"./images/DebugStart.png", dpi=200)
    fig.clear()
    test.removeUser(Users[2])
    fig = Tree.draw_tree_matplotlib(test.root, maxY=7)
    fig.savefig(f"./images/DebugR3.png", dpi=200)
    fig.clear()
    test.removeUser(Users[0])
    fig = Tree.draw_tree_matplotlib(test.root, maxY=7)
    fig.savefig(f"./images/DebugR1.png", dpi=200)
    fig.clear()

    for i in test.depth:
        print(f"Layer {i}: {test.depth[i]}")

    test.removeUser(Users[1])
    fig = Tree.draw_tree_matplotlib(test.root, maxY=7)
    fig.savefig(f"./images/DebugR2.png", dpi=200)
    fig.clear()

    test.removeUser(Users[3])
    fig = Tree.draw_tree_matplotlib(test.root, maxY=7)
    fig.savefig(f"./images/DebugR4.png", dpi=200)
    fig.clear()


def randomTest(n=10000, nuser=256):
    test = Tree.LKH(TestUser.sendGroup, debug=False)
    Users = [TestUser() for i in range(nuser)]
    isInGraph = [0] * nuser
    Actions = []
    naiveCount = 0
    for essais in tqdm(range(n)):
        i = random.randrange(0, nuser)
        try:
            # fig_before = Tree.draw_tree_matplotlib(test.root,maxY=7)
            naiveCount += sum(isInGraph)
            if isInGraph[i]:
                test.removeUser(Users[i])
                Actions.append(f"Rem {Users[i].userID}")
            else:
                test.addUser(Users[i])
                Actions.append(f"Add {Users[i].userID}")
            # fig_before.clear()
            # print(test.depth)
            # input(f"{Actions[-1]}")

        except Exception as e:
            traceback.print_exc()
            print(
                f"Error for node [{"Join" if not isInGraph[i] else "Leave"}] {Users[i]} "
            )
            # print(test)
            print("Nodes : ")
            print(f"Stored keyIds : {list(test.nodes.keys())}")
            for n in test.nodes:
                ln = test.nodes[n]
                print(f"{ln.id}, {ln.keyid}")
            # print(f"Error : {e.with_traceback(None)}")

            print(test.depth)
            print(Actions)
            print(test)
            fig = Tree.draw_tree_matplotlib(test.root, maxY=7)

            # fig.savefig(f"./images/DebugR4.png",dpi=200)
            plt.show()
            fig.clear()

            exit(-1)
        isInGraph[i] = 1 - isInGraph[i]
    print(f"Total Keys at the end : {len(test.nodes.keys())}")
    print(f"Multicasts Messages : {TestUser.numberOfMulticast}")
    print(f"Unicast Messages : {TestUser.numberOfUnicast}")
    print(f"Unicast Message in Naïve method: {naiveCount}")
    print(
        f"Ratio : {(TestUser.numberOfMulticast+TestUser.numberOfUnicast)*100/naiveCount:.2f}%"
    )


def interractiveTest():
    test = Tree.LKH(TestUser.sendGroup, debug=True)
    Users = [TestUser() for i in range(10)]
    isInGraph = [0] * 10
    fig, ax = plt.subplots(figsize=(20, 10))

    plt.ion()
    plt.show()
    while True:
        try:
            print(test)
            i = int(input(">>>")) - 1
            if isInGraph[i]:
                test.removeUser(Users[i])
            else:
                test.addUser(Users[i])
            isInGraph[i] = 1 - isInGraph[i]
            for i in test.nodes:
                nl = test.nodes[i]
                print(f"Parent of {nl} is ==> {nl.parent}")
            ax.clear()
            Tree.draw_tree_matplotlib(test.root, maxY=7, ax=ax)
            print(test.depth)
            plt.pause(0.1)

        except Exception as e:
            if type(e) is KeyboardInterrupt:
                exit(0)
            if type(e) is AssertionError:
                traceback.print_exc()
                print(test)

                input()
                exit(-1)
            else:
                traceback.print_exc()
                print(test)


def dynamicDemo(n=100):

    test = Tree.LKH(TestUser.sendGroup, debug=True)
    Users = [TestUser() for i in range(n)]
    isInGraph = [0] * n
    fig, ax = plt.subplots(figsize=(20, 10))
    while True:
        TestUser.reset()
        i = random.randrange(0, n)
        if isInGraph[i]:
            test.removeUser(Users[i])
        else:
            test.addUser(Users[i])
        isInGraph[i] = 1 - isInGraph[i]
        stats = TestUser.getStats()
        ax.clear()
        Tree.draw_tree_matplotlib(test.root, maxY=7, ax=ax, specialKeys=stats["keys"])
        print(test.depth)
        plt.pause(0.1)


def testGroup():
    test = Tree.LKH(TestUser.sendGroup, debug=True)
    Users = [TestUser() for i in range(10)]
    test.addUserGroup(Users[:1])
    for user in Users:
        print(user)
    print(test)

    test.addUserGroup(Users[1:3])
    print(test)
    for user in Users:
        print(user)
    test.addUserGroup(Users[3:8])
    print(test)
    for user in Users:
        print(user)


if __name__ == "__main__":

    # test_Add()
    # test_del()
    # show_draw()
    # show_Worst_Case_remove()
    # randomTest(n=20000,nuser=8)
    """TestUser.realist= False #Remove decryption, takes too long
    print("Test with 8 users and 256 actions\n")
    randomTest(nuser=8,n=256)
    TestUser.reset()
    print("Test with 256 users and 10000 actions\n")
    randomTest()
    TestUser.reset()
    print("Test with 10**4 users and 10**6 actions\n")
    randomTest(n=10**6,nuser=10**4)
    TestUser.reset()"""

    # interractiveTest()

    testGroup()

    # dynamicDemo()
    pass
