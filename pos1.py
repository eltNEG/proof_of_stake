from datetime import datetime
import time
import hashlib
import json
import requests
from random import randint
from typing import List
import random

#from rsa import PublicKey


class Node:
    def __init__(self, privKey, public_key, weight, age):
        self.private_key = privKey
        self.public_key = public_key
        self.landamt = weight
        self.age = age
        self.left = None
        self.right = None

    def __str__(self):
        return str(self.public_key)

    def copy(self):
        return Node(self.private_key, self.public_key, self.weight, self.age)

    def isValid(self):
        if(self.private_key != None and self.public_key != None and self.weight != None and self.age != None):
            return False
        return True

    def hash(self):
        return hashlib.sha256(str(self.private_key).encode('utf-8')).hexdigest()


class MerkleTree:
    def __init__(self, values: List[str]) -> None:
        self.__buildTree(values)

    def __buildTree(self, values: List[str]) -> None:

        leaves: List[Node] = [Node(None, None, Node.hash(e), e)
                              for e in values]
        if len(leaves) % 2 == 1:
            # duplicate last elem if odd number of elements
            leaves.append(leaves[-1].copy())
        self.root: Node = self.__buildTreeRec(leaves)

    def __buildTreeRec(self, nodes: List[Node]) -> Node:
        if len(nodes) % 2 == 1:
            # duplicate last elem if odd number of elements
            nodes.append(nodes[-1].copy())
        half: int = len(nodes) // 2

        if len(nodes) == 2:
            return Node(nodes[0], nodes[1], Node.hash(nodes[0].value + nodes[1].value), nodes[0].content+"+"+nodes[1].content)

        left: Node = self.__buildTreeRec(nodes[:half])
        right: Node = self.__buildTreeRec(nodes[half:])
        value: str = Node.hash(left.value + right.value)
        content: str = f'{left.content}+{right.content}'
        return Node(left, right, value, content)

    def printTree(self) -> None:
        self.__printTreeRec(self.root)

    def __printTreeRec(self, node: Node) -> None:
        if node != None:
            if node.left != None:
                print("Left: "+str(node.left))
                print("Right: "+str(node.right))
            else:
                print("Input")

            if node.is_copied:
                print('(Padding)')
            print("Value: "+str(node.value))
            print("Content: "+str(node.content))
            print("")
            self.__printTreeRec(node.left)
            self.__printTreeRec(node.right)

    def getRootHash(self) -> str:
        return self.root.value


class Transaction():
    """Transaction class"""

    def __init__(self, seller, buyer, propertyId, amount, timestamp):
        self.seller = seller
        self.buyer = buyer
        self.amount = amount
        self.timestamp = timestamp
        self.propertyId = propertyId
        self.history = []

    def setSeller(self):
        pubKeySel = input("Enter seller's public key: ")
        privKeySel = input("Enter seller's private key: ")

        seller = Node(privKeySel, pubKeySel, 0, 0)
        return seller

    def setBuyer(self):
        pubKeyBuy = input("Enter buyer's public key: ")
        privKeyBuy = input("Enter buyer's private key: ")

        buyer = Node(privKeyBuy, pubKeyBuy, 0, 0)
        return buyer

    def registerForTransactions(self, details):
        details = input("Enter new node details for registration: ")
        self.public_key = hashlib.sha1(details.encode('utf-8')).hexdigest()

        key = input("Enter private key: ")
        if(key == self.setSeller().private_key or key == self.setBuyer().private_key):
            return self.public_key
        return False

    def authorize(self):
        pubKey = self.setSeller().public_key

        tsignature = self.registerForTransactions(self.setSeller())
        if(tsignature == pubKey):
            return True
        return False
        # verify signature

        # signature = checkSignature(transaction body, public key)

        # tsignature === signature ? true : false

    def sign(self, privKeySel, privKeyBuy, number):

        return hashlib.blake2b(digest_size=16, key=privKeySel + privKeyBuy + number).digest()
        # sign transaction

    def signTransaction(self):
        # public key, private key
        self.history.append({"seller": self.seller, "publicKey": self.setSeller().public_key, "timestamp": self.timestamp})

        nonce = random.randint(1, 10)  # random number

        signature = self.sign(self.setSeller().private_key,
                              self.setBuyer().private_key, nonce)
        return signature


class Block():
    def __init__(self, timeStamp, merkleroot, prevhash, transactions=[]):
        self.timeStamp = timeStamp
        self.merkleroot = merkleroot
        self.prevhash = prevhash
        self.nonce = 0
        self.transactions = transactions

    def addTransactions(self, transaction):
        if (transaction.authorize() and transaction.signTransaction()):
            self.transactions.append(transaction)
            return True
        return False

    def getHash(self):
        return hashlib.sha256(str(self.timeStamp).encode('utf-8') + str(self.merkleroot).encode('utf-8') + str(self.prevhash).encode('utf-8') + str(self.nonce).encode('utf-8')).hexdigest()


class Blockchain():

    def __init__(self, _genesisBlock, account):
        """
            If the genesis block is valid, create chain
        """
        self.blockChain = []
        self.tempBlocks = []
        # self.candidateBlocks = [] #constains block
        self.myCurrBlock = {}
        #self.announcements = []
        self.validators = set()  # stakers and balance
        #self.unconfirmed_txns = []
        self.nodes = set()
        self.myAccount = {'Address': '', 'Weight': 0, 'Age': 0}
        self.myAccount['Address'] = account['Address']
        self.myAccount['Weight'] = account['Weight']
        try:
            genesisBlock = self.generate_genesis_block(_genesisBlock)
            if self.is_block_valid(genesisBlock):
                self.blockChain.append(genesisBlock)
            else:
                raise Exception('Unable to verify block')
        except Exception as e:
            print('Invalid genesis block.\nOR\n' + str(e))

    def is_block_valid(self, block, prevBlock={}):
        try:
            _hash = block['Hash']
        except KeyError as e:
            return False
        try:
            hash2 = self.hasher(block)
            assert _hash == hash2
        except AssertionError as e:
            return False

        prevHash = prevBlock['Hash'] if prevBlock else ''
        block['Hash'] = _hash
        # obj of merkel tree
        obj_mrkl_tree = MerkleTree(block['Transactions'])
        obj_mrkl_tree.getRootHash()
        if self.blockChain:
            prevHash = self.blockChain[-1]['Hash'] if not prevHash else prevHash
            try:
                assert prevHash == block["PrevHash"]
            except AssertionError as e:
                if prevHash == self.blockChain[0]['Hash']:
                    block['Hash'] = _hash
                    return True
                block['Hash'] = _hash
                return False
        block['Hash'] = _hash
        return True

    def generate_new_block(self, bpm=randint(53, 63), oldBlock='', address=''):
        if self.myCurrBlock:
            return self.myCurrBlock
        prevHash = self.blockChain[-1]['Hash']
        index = len(self.blockChain) if not oldBlock else oldBlock['Index'] + 1
        address = self.get_validator(
            self.myAccount) if not address else address
        newBlock = {
            "Index": index,
            "Timestamp": str(datetime.now()),
            "BPM": bpm,  # instead of transactions
            "PrevHash": prevHash,
            "Validator": address
        }
        newBlock["Hash"] = self.hasher(newBlock)
        assert self.is_block_valid(newBlock)
        self.myCurrBlock = newBlock
        return newBlock

    def get_blocks_from_nodes(self):
        if self.nodes:
            for node in self.nodes:
                #resp = requests.get('http://{}/newblock'.format(node))
                node.add_another_block(self.myCurrBlock)
                resp = node.generate_new_block()
                if self.is_block_valid(resp):  # resp.json()
                    # self.tempBlocks.append(resp.json())
                    if not resp['Validator'] in self.validators:
                        self.tempBlocks.append(resp)
                        self.validators.add(resp['Validator'])

    def add_another_block(self, another_block):
        if self.is_block_valid(another_block):
            if not another_block['Validator'] in self.validators:
                self.tempBlocks.append(another_block)
                self.validators.add(another_block['Validator'])

    def pick_winner(self):
        """Creates a lottery pool of validators and choose the validator
            who gets to forge the next block. Random selection weighted by amount of token staked

            Do this every 30 seconds
        """
        winner = []

        self.tempBlocks.append(self.myCurrBlock)
        self.validators.add(self.myCurrBlock['Validator'])
        for validator in self.validators:
            acct = (validator.rsplit(sep=', '))
            acct.append(int(acct[1]) * int(acct[2]))
            if winner and acct[-1]:
                winner = acct if winner[-1] < acct[-1] else winner
            else:
                winner = acct if acct[-1] else winner
        if winner:
            return winner
        for validator in self.validators:
            acct = (validator.rsplit(sep=', '))
            acct.append((int(acct[1]) + int(acct[2]))/len(acct[0]))
            if winner:
                winner = acct if winner[-1] < acct[-1] else winner
            else:
                winner = acct
        return winner

    def pos(self):
        """
        #get other's stakes
        #add owns claim
        #pick winner
        """

        print(str(self.myAccount) +
              ' =======================> Getting Valid chain\n')
        self.resolve_conflict()
        self._pos()
        print('***Calling other nodes to announce theirs***' + "\n")
        for node in self.nodes:
            node._pos()
        for block in self.tempBlocks:
            validator = block['Validator'].rsplit(', ')
            if validator[0] == self.pick_winner()[0]:
                new_block = block
                break
            else:
                pass
        print('New Block ====> ' + str(new_block) + "\n")
        time.sleep(1)
        self.add_new_block(new_block)
        for node in self.nodes:
            node.add_new_block(new_block)
        print('Process ends' + "\n")

    def announce_winner(self):
        self.blockChain.append(self.myCurrBlock)

    def add_new_block(self, block):
        if self.is_block_valid(block):
            # check index too
            self.blockChain.append(block)
            acct = block['Validator'].rsplit(', ')
            if self.myAccount['Address'] != acct[0]:
                self.myAccount['Age'] += 1
            else:
                self.myAccount['Weight'] += (randint(1, 10)
                                             * self.myAccount['Age'])
                self.myAccount['Age'] = 0
        self.tempBlocks = []
        self.myCurrBlock = {}
        self.validators = set()

    def resolve_conflict(self):
        for node in self.nodes:
            if len(node.blockChain) > len(self.blockChain):
                if self.is_chain_valid(node.blockChain):
                    print('***Replacing node***' + "\n")
                    self.blockChain = node.blockChain
                    return
        print('***My chain is authoritative***' + "\n")
        return

    def is_chain_valid(self, chain):
        _prevBlock = ''
        for block in chain:
            if self.is_block_valid(block, prevBlock=_prevBlock):
                _prevBlock = block
            else:
                return False
        return True

    def add_new_node(self, new_node):
        self.nodes.add(new_node)
        new_node.add_another_node(self)

    def add_another_node(self, another_node):
        self.nodes.add(another_node)

    @staticmethod
    def hasher(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @staticmethod
    def get_validator(address):
        return ', '.join([address['Address'], str(address['Weight']), str(address['Age'])])

    def generate_genesis_block(self, genesisblock):
        address = {'Address': 'eltneg', 'Weight': 50, 'Age': 0}
        address = self.get_validator(address)
        genesisblock['Index'] = 0 if not genesisblock['Index'] else genesisblock['Index']
        genesisblock['Timestamp'] = str(
            datetime.now()) if not genesisblock['Timestamp'] else genesisblock['Timestamp']
        genesisblock['BPM'] = 0 if not genesisblock['BPM'] else genesisblock['BPM']
        genesisblock['PrevHash'] = '0000000000000000'
        genesisblock['Validator'] = address if not genesisblock['Validator'] else genesisblock['Validator']
        genesisblock['Hash'] = self.hasher(genesisblock)
        return genesisblock
