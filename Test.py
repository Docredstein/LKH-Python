#!/bin/python
from uuid import uuid4
import Tree
from colorama import Fore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import matplotlib.pyplot as plt
import random
from tqdm import tqdm
import traceback
import numpy as np
from matplotlib.ticker import MaxNLocator

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
        if len(key)<=0 :
            print(f"[{keyId} : {key}]")
        
        aesgcm = AESGCM(key)
        try:
            clear = aesgcm.decrypt(nonce=nonce, data=ct, associated_data=rawkeyId)
            UpdatePacket = Tree.KeyUpdatePacket.fromBytes(clear)
        except InvalidTag as e:
            # print(f"Invalid decrypt for {self.userID} {e}")
            return
        # print(f"{self.userID} received group key {UpdatePacket.newKeyid}")
        self.keys[UpdatePacket.newKeyid] = UpdatePacket.newKey
        if len( UpdatePacket.newKey) <= 0 :
            print(f"new key : { UpdatePacket.newKey}")
            input()
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
    def reset(full=True):
        TestUser.changedKeys = set()
        TestUser.numberOfMulticast = 0
        TestUser.numberOfUnicast = 0
        if full:
            TestUser.totalCount = 0 
            TestUser.instances.clear()

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
def test_del_worst():
    test = Tree.LKH(TestUser.sendGroup, debug=True)
    Users = [TestUser() for i in range(5)]

    printUsers = lambda: print("\n".join([str(i) for i in Users]))
    
    for user in Users : 
        test.addUser(user)
    Tree.draw_tree_matplotlib(test.root)
    if not checkSessionKey(Users,[1]*5,test) : 
        raise Exception("Incorrect Tree")
    #plt.show()
    test.removeUser(Users[2])
    printUsers()
    if not checkSessionKey(Users,[1,1,0,1,1],test) : 
        raise Exception("Incorrect Tree")
    Tree.draw_tree_matplotlib(test.root)
    #plt.show()

def show_draw(n=32):
    test = Tree.LKH(TestUser.sendGroup, debug=True)
    Users = [TestUser() for i in range(n)]

    for i in Users:
        test.addUser(i)
        stats = TestUser.getStats()
        TestUser.reset(full=False)
        fig = Tree.draw_tree_matplotlib(test.root, maxY=4, specialKeys=stats["keys"],fontsize=36)

        fig.savefig(f"./images/Rapporttree_A{int(i.userID):02d}.svg", dpi=200)
        fig.clear()

    for i in Users:
        print(test.depth)
        #input("")
        test.removeUser(i)
        stats = TestUser.getStats()
        TestUser.reset(full=False)
        fig = Tree.draw_tree_matplotlib(test.root, maxY=4, specialKeys=stats["keys"],fontsize=36)
        fig.savefig(f"./images/Rapporttree_R{int(i.userID):02d}.svg", dpi=200)
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
def checkSessionKey(Users:list[TestUser],inTree:list[bool], tree:Tree.LKH) :
    sessionKey = tree.root.key
    sessionKeyId = tree.root.keyid
    for i in range(len(inTree)) :
        hasKey = sessionKeyId in Users[i].keys and Users[i].keys[sessionKeyId]==sessionKey and Users[i].sessionKey==sessionKeyId

        if (inTree[i]!=hasKey) : 
            print(f"i : {i}")
            print(f"Session key id : {sessionKeyId}")
            print(f"Session key : {sessionKey.hex()}")
            print(f"intree : {inTree[i]}")
            print(f"Know key id : {sessionKeyId in Users[i].keys}")
            print(Users[i])
            print(f"has correct key : {Users[i].keys[sessionKeyId]==sessionKey}")
            print(f"Know if session key ? : {Users[i].sessionKey==sessionKeyId}")
            
            return False
    return True
        


def randomTest(n=10000, nuser=256):
    test = Tree.LKH(TestUser.sendGroup, debug=False)
    TestUser.reset()
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
            isInGraph[i] = 1 - isInGraph[i]
            if not checkSessionKey(Users,isInGraph,test) :
                raise Exception("Incorrect session Key")
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
            print(Users)
            fig = Tree.draw_tree_matplotlib(test.root, maxY=7)

            # fig.savefig(f"./images/DebugR4.png",dpi=200)
            plt.show()
            fig.clear()

            exit(-1)
        
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

def testLKHPlus() : 
    test = Tree.LKHPlus(TestUser.sendGroup, debug=False,allowableUnorderedUserCount=4
                        )
    Users = [TestUser() for i in range(10)]
    for i in range(10):
        test.addUser(Users[i])
        print(test)
    for i in range(10): 
        print(f"Removing {Users[i]}")
        test.removeUser(Users[i])
        print(test)

def getCompareMessageForN(ns :list[int], maxUsers : list[int],repetition=10,annoyingUser=False ) :
    out = []
    # name -> list[dict[str,list[int]]]  
    for rep in tqdm(range(repetition)) :
        current_exp = {"Naive":[],"LKH":[],"LKHPlus":[]}
        for n in ns :

            random.seed(rep)
            TestUser.reset()
            test = Tree.LKH(TestUser.sendGroup, debug=False)
            Users = [TestUser() for i in range(n)]
            isInGraph = [0] * n
            Actions = []
            naiveCount = 0
            for _ in range(15*n):
                if not annoyingUser :
                    i = random.randrange(0, n)
                else :
                    i = min(random.randrange(0, 2*n),n-1)
                
                # fig_before = Tree.draw_tree_matplotlib(test.root,maxY=7)
                naiveCount += sum(isInGraph)
                if isInGraph[i]:
                    test.removeUser(Users[i])
                    
                else:
                    test.addUser(Users[i])
                isInGraph[i] = 1 - isInGraph[i]
            current_exp["LKH"].append(TestUser.getStats())
            current_exp["Naive"].append(naiveCount)
        Y_LKH = [ i["multicast"]+i["unicast"] for i in current_exp["LKH"]]
        Y_Naive = [i for i in current_exp["Naive"]]

        OUT_lkhp = {}
        for maxUser in maxUsers :
            current_exp["LKHPlus"] = []
            for n in ns :
                random.seed(rep)
                TestUser.reset()
                test = Tree.LKHPlus(TestUser.sendGroup, debug=False,allowableUnorderedUserCount=maxUser)
                Users = [TestUser() for i in range(n)]
                isInGraph = [0] * n
                Actions = []
                naiveCount = 0
                for _ in range(15*n):
                    if not annoyingUser :
                        i = random.randrange(0, n)
                    else :
                        i = min(random.randrange(0, 2*n),n-1)
                    
                    # fig_before = Tree.draw_tree_matplotlib(test.root,maxY=7)
                    naiveCount += sum(isInGraph)
                    if isInGraph[i]:
                        test.removeUser(Users[i])
                        
                    else:
                        test.addUser(Users[i])
                    isInGraph[i] = 1 - isInGraph[i]
                #print(f"Naive : {naiveCount}")
                current_exp["LKHPlus"].append(TestUser.getStats())
            Y_LKHPlus = [ i["multicast"]+i["unicast"] for i in current_exp["LKHPlus"]]
            OUT_lkhp[maxUser] = Y_LKHPlus
        out.append({"Naive":Y_Naive,"LKH":Y_LKH,"LKHP":OUT_lkhp})
    return out
def compareMessageWithSTD(ns :list[int], maxUsers : list[int],repetition=10,alpha=0.1,showUnicast=True,filename="comparaison-std.svg",AnnoyingUser=False) :
    # source : https://allanchain.github.io/blog/post/mpl-paper-tips/
    params_basic = {
    "xtick.direction": "in",  # Ticks point inward
    "xtick.minor.visible": True,  # Show minor ticks
    "ytick.direction": "in",
    "ytick.minor.visible": True,
    "legend.frameon": False,  # Remove legend border
    
    }
     
    params_thin = {
    "xtick.major.size": 3,
    "xtick.major.width": 0.5,
    "xtick.minor.size": 1.5,
    "xtick.minor.width": 0.5,
    "ytick.major.size": 3,
    "ytick.major.width": 0.5,
    "ytick.minor.size": 1.5,
    "ytick.minor.width": 0.5,
    "axes.linewidth": 0.5,
    "grid.linewidth": 0.5,
    "lines.linewidth": 1.0,
    }   

    params_serif = {
    **params_basic,
    **params_thin,
    "font.family": "serif",
    "font.serif": ["cmr10"],
    "axes.formatter.use_mathtext": True,
    "mathtext.fontset": "cm",
    }
    data = getCompareMessageForN(ns, maxUsers,repetition,annoyingUser=AnnoyingUser)
    Naives = np.asarray([a["Naive"] for a in data])
    LKHs = np.asarray([a["LKH"] for a in data])
    LKHPs = {}
    #print([a["LKHP"].keys() for a in data])
    for i in maxUsers :
        LKHPs[i]= np.asarray([a["LKHP"][i]for a in data])
    #print(LKHPs)
    plt.figure()
    Naive_mean = np.mean(Naives,axis=0)
    Naive_std = np.std(Naives,axis=0,ddof=1)

    LKH_mean = np.mean(LKHs,axis=0)
    LKH_std = np.std(LKHs,axis=0,ddof=1)
    print(LKHPs)
    LKHp_mean = {i:np.mean(LKHPs[i],axis=0) for i in maxUsers}
    LKHp_std = {i:np.std(LKHPs[i],axis=0,ddof=1) for i in maxUsers}
    plt.rcParams["svg.fonttype"]="none"
    with plt.style.context(params_serif):
    #print(Naives.shape)
        if showUnicast:
            plt.plot(ns,Naive_mean, "r-", label="Unicast uniquement")
            plt.fill_between(ns,Naive_mean-Naive_std,Naive_mean+Naive_std,color="#f0627a",alpha=alpha)

        plt.plot(ns,LKH_mean, "b-", label="LKH")
        plt.fill_between(ns,LKH_mean-LKH_std,LKH_mean+LKH_std,color="#6281f0",alpha=alpha)
        
        for i in maxUsers : 
            color = plt.plot(ns,LKHp_mean[i], label=f"LKH+ avec max\\_user = {i}")[0].get_color()
            plt.fill_between(ns,LKHp_mean[i]-LKHp_std[i],LKHp_mean[i]+LKHp_std[i],color=color,alpha=alpha)

        plt.gca().xaxis.set_major_locator(MaxNLocator(integer=True))
        plt.legend()
        
        plt.ylabel("Nombre de chiffrements totaux")
        plt.xlabel("Nombre d'utilisateurs ($n$)")
        plt.suptitle(f"Nombre de chiffrements pour $15n$ actions {"équiprobables" if not AnnoyingUser else "biaisées"}")
        plt.grid()
        plt.savefig("./images/"+filename)
        #plt.show()

def compareNumberMessageForN(ns :list[int]) :
    maxUser = 32
    out = {"Naive":[],"LKH":[],"LKHPlus":[]}
    plt.figure()
    for n in tqdm(ns) :

        random.seed(0)
        TestUser.reset()
        test = Tree.LKH(TestUser.sendGroup, debug=False)
        Users = [TestUser() for i in range(n)]
        isInGraph = [0] * n
        Actions = []
        naiveCount = 0
        for _ in range(15*n):
            i = random.randrange(0, n)
            
            # fig_before = Tree.draw_tree_matplotlib(test.root,maxY=7)
            naiveCount += sum(isInGraph)
            if isInGraph[i]:
                test.removeUser(Users[i])
                
            else:
                test.addUser(Users[i])
            isInGraph[i] = 1 - isInGraph[i]
        out["LKH"].append(TestUser.getStats())
        out["Naive"].append(naiveCount)
    Y_LKH = [ i["multicast"]+i["unicast"] for i in out["LKH"]]
    Y_Naive = [i for i in out["Naive"]]
    plt.plot(ns,Y_Naive, "r-", label="Unicast uniquement")
    plt.plot(ns,Y_LKH,"b-",label="LKH")
    for maxUser in [8,16,64,128] :
        out["LKHPlus"] = []
        for n in tqdm(ns) :
            random.seed(0)
            TestUser.reset()
            test = Tree.LKHPlus(TestUser.sendGroup, debug=False,allowableUnorderedUserCount=maxUser)
            Users = [TestUser() for i in range(n)]
            isInGraph = [0] * n
            Actions = []
            naiveCount = 0
            for _ in range(15*n):
                i = random.randrange(0, n)
                
                # fig_before = Tree.draw_tree_matplotlib(test.root,maxY=7)
                naiveCount += sum(isInGraph)
                if isInGraph[i]:
                    test.removeUser(Users[i])
                    
                else:
                    test.addUser(Users[i])
                isInGraph[i] = 1 - isInGraph[i]
            #print(f"Naive : {naiveCount}")
            out["LKHPlus"].append(TestUser.getStats())
        Y_LKHPlus = [ i["multicast"]+i["unicast"] for i in out["LKHPlus"]]
        print(f"Ratio for {maxUser} : {Y_LKHPlus[-1]/Y_LKH[-1]}")
        plt.plot(ns,Y_LKHPlus,label=f"LKHPlus (max_user = {maxUser})")
    plt.legend()
    
    plt.ylabel("Nombre de chiffrements totaux")
    plt.xlabel("Nombre d'utilisateurs ($n$)")
    plt.suptitle("Nombre de chiffrement pour $15n$ actions aléatoires")
    plt.grid()

    plt.savefig("./images/comparaison.svg")
    plt.show()

def compareNumberMessageForNAnnoyingUser(ns :list[int],showUnicast=True) :
    maxUser = 32
    out = {"Naive":[],"LKH":[],"LKHPlus":[]}
    plt.figure()
    
    for n in tqdm(ns) :
        random.seed(0)
        TestUser.reset()
        test = Tree.LKH(TestUser.sendGroup, debug=False)
        Users = [TestUser() for i in range(n)]
        isInGraph = [0] * n
        Actions = []
        naiveCount = 0
        for _ in range(15*n):
            i = min(random.randrange(0, 2*n),n-1)

            
            # fig_before = Tree.draw_tree_matplotlib(test.root,maxY=7)
            naiveCount += sum(isInGraph)
            if isInGraph[i]:
                test.removeUser(Users[i])
                
            else:
                test.addUser(Users[i])
            isInGraph[i] = 1 - isInGraph[i]
        out["LKH"].append(TestUser.getStats())
        out["Naive"].append(naiveCount)
    Y_LKH = [ i["multicast"]+i["unicast"] for i in out["LKH"]]
    if showUnicast:
        Y_Naive = [i for i in out["Naive"]]
        plt.plot(ns,Y_Naive, "r-", label="Unicast uniquement")
    plt.plot(ns,Y_LKH,"b-",label="LKH")
    for maxUser in [8,16,64,128] :
        out["LKHPlus"] = []
        for n in tqdm(ns) :
            random.seed(0)
            TestUser.reset()
            test = Tree.LKHPlus(TestUser.sendGroup, debug=False,allowableUnorderedUserCount=maxUser)
            Users = [TestUser() for i in range(n)]
            isInGraph = [0] * n
            Actions = []
            naiveCount = 0
            for _ in range(15*n):
                i = min(random.randrange(0, 2*n),n-1)
                
                # fig_before = Tree.draw_tree_matplotlib(test.root,maxY=7)
                naiveCount += sum(isInGraph)
                if isInGraph[i]:
                    test.removeUser(Users[i])
                    
                else:
                    test.addUser(Users[i])
                isInGraph[i] = 1 - isInGraph[i]
            #print(f"Naive : {naiveCount}")
            out["LKHPlus"].append(TestUser.getStats())
        Y_LKHPlus = [ i["multicast"]+i["unicast"] for i in out["LKHPlus"]]
        print(f"Ratio for {maxUser} : {Y_LKHPlus[-1]/Y_LKH[-1]}")
        plt.plot(ns,Y_LKHPlus,label=f"LKHPlus (max_user = {maxUser})")
    plt.legend()
    
    plt.ylabel("Nombre de chiffrements totaux")
    plt.xlabel("Nombre d'utilisateurs ($n$)")
    plt.suptitle("Nombre de chiffrement pour $15n$ actions aléatoires")
    plt.grid()

    plt.savefig("./images/comparaison4.svg")
def compare_max_user(ns:list[int],max_users:list[int]) : 
    Y_LKH = []
    for n in ns : 
        random.seed(0)
        TestUser.reset()
        test = Tree.LKH(TestUser.sendGroup, debug=False)
        Users = [TestUser() for i in range(n)]
        isInGraph = [0] * n
        Actions = []
        naiveCount = 0
        for _ in range(15*n):
            i = random.randrange(0, n)
            
            # fig_before = Tree.draw_tree_matplotlib(test.root,maxY=7)
            naiveCount += sum(isInGraph)
            if isInGraph[i]:
                test.removeUser(Users[i])
                
            else:
                test.addUser(Users[i])
            isInGraph[i] = 1 - isInGraph[i]
        stat = TestUser.getStats()
        Y_LKH.append(stat)
    print("LKH done")
    Y_LKHPLUS = {}
    for max_user in tqdm(max_users) : 
        Y_LKHPLUS[max_user] = []
        for n in ns : 
            random.seed(0)
            TestUser.reset()
            test = Tree.LKH(TestUser.sendGroup, debug=False)
            Users = [TestUser() for i in range(n)]
            isInGraph = [0] * n
            Actions = []
            naiveCount = 0
            for _ in range(15*n):
                i = random.randrange(0, n)
                
                # fig_before = Tree.draw_tree_matplotlib(test.root,maxY=7)
                naiveCount += sum(isInGraph)
                if isInGraph[i]:
                    test.removeUser(Users[i])
                    
                else:
                    test.addUser(Users[i])
                isInGraph[i] = 1 - isInGraph[i]
            stat = TestUser.getStats()
            Y_LKHPLUS[max_user].append(stat)
    plt.subplot(1,3,1)
    plt.plot(ns,[i["unicast"] for i in Y_LKH],label="LKH")
    for i in Y_LKHPLUS :
        plt.plot(ns, [j["unicast"]for j in Y_LKHPLUS[i]],label=f"LKHPlus (Max_user = {i})")
    plt.ylabel("Nombre de message unicast")
    plt.xlabel("Nombre d'utilisateur")
    plt.title("Unicast")
    plt.legend()
    plt.subplot(1,3,2)
    plt.plot(ns,[i["multicast"] for i in Y_LKH],label="LKH")
    for i in Y_LKHPLUS :
        plt.plot(ns, [j["multicast"]for j in Y_LKHPLUS[i]],label=f"LKHPlus (Max_user = {i})")
    plt.ylabel("Nombre de message multicast")
    plt.xlabel("Nombre d'utilisateur")
    plt.title("Multicast")
    plt.legend()
    plt.subplot(1,3,3)

    plt.plot(ns,[Y_LKH[j]["unicast"] +Y_LKH[j]["multicast"] for j in range(len(Y_LKH))  ],label="LKH")
    for i in Y_LKHPLUS :
        plt.plot(ns, [Y_LKHPLUS[i][j]["unicast"] +Y_LKHPLUS[i][j]["multicast"] for j in range(len(Y_LKHPLUS[i]))   ],label=f"LKHPlus (Max_user = {i})")
    plt.ylabel("Nombre de message total")
    plt.xlabel("Nombre d'utilisateur")
    plt.title("Total")
    plt.legend()
    plt.savefig("Comparaison_LKHPLus.svg")
    plt.show()


    


if __name__ == "__main__":

    # test_Add()
    #test_del()
    #test_del_worst()
    # show_draw()
    #show_Worst_Case_remove()
    randomTest(n=20000,nuser=32)
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
    #compareNumberMessageForN([10*i for i in range(100)])
    #compareMessageWithSTD([50*i for i in range(20)],[2,8,64,128],AnnoyingUser=False,filename="ComparaisonUNIFLarge.svg")
    #compareMessageWithSTD([10*i for i in range(20)],[2,8,64,128],AnnoyingUser=False,filename="ComparaisonUNIFClose.svg")
    #compareMessageWithSTD([50*i for i in range(20)],[2,8,64,128],AnnoyingUser=True,showUnicast=False,filename="ComparaisonAnnoyingLarge.svg")
    #compareMessageWithSTD([10*i for i in range(20)],[2,8,64,128],AnnoyingUser=True,showUnicast=False,filename="ComparaisonAnnoyingClose.svg")
    #compareNumberMessageForNAnnoyingUser([10*i for i in range(100)],showUnicast=False)
    #compare_max_user([2**i for i in range(12)],max_users=[2,8,16])
    # interractiveTest()

    #testGroup()
    #testLKHPlus()
    # dynamicDemo()
    #show_draw(5)
    pass
