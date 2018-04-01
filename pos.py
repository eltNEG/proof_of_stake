"""
    Python implementation of POW
    Credit: https://github.com/mycoralhealth/blockchain-tutorial
"""
from datetime import datetime
import time
from hashlib import sha256
import json, requests
from random import randint


DATE = datetime.now()
GENESIS_BLOCK = {
    "Index": 0,
    "Timestamp": str(DATE),
    "BPM": 0, #instead of transactions
    "PrevHash": "",
    "Validator": "" #address to receive the reward {validator, weight, age}
}
GENESIS_BLOCK2 = {
    "Index": 0,
    "Timestamp": str(DATE),
    "BPM": 0, #instead of transactions
    "PrevHash": "",
    "Validator": "" #address to receive the reward {validator, weight, age}
}
GENESIS_BLOCK3 = {
    "Index": 0,
    "Timestamp": str(DATE),
    "BPM": 0, #instead of transactions
    "PrevHash": "",
    "Validator": "" #address to receive the reward {validator, weight, age}
}

GENESIS_BLOCK4 = {
    "Index": 0,
    "Timestamp": str(DATE),
    "BPM": 0, #instead of transactions
    "PrevHash": "",
    "Validator": "" #address to receive the reward {validator, weight, age}
}


class Blockchain(object):
    

    def __init__(self, _genesisBlock, account):
        """
            If the genesis block is valid, create chain
        """
        self.blockChain = []
        self.tempBlocks = []
        #self.candidateBlocks = [] #constains block
        self.myCurrBlock = {}
        #self.announcements = []
        self.validators = set() # stakers and balance
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
            _hash = block.pop('Hash')
        except KeyError as e:
            return False
        try:
            hash2 = self.hasher(block)
            assert _hash == hash2
        except AssertionError as e:
            return False
            
        prevHash = prevBlock['Hash'] if prevBlock else ''
        block['Hash'] = _hash
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
        address =  self.get_validator(self.myAccount) if not address else address
        newBlock = {
            "Index": index,
            "Timestamp": str(datetime.now()),
            "BPM": bpm, #instead of transactions
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
                if self.is_block_valid(resp): #resp.json()
                    #self.tempBlocks.append(resp.json())
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

        print(str(self.myAccount) + ' =======================> Getting Valid chain\n')
        self.resolve_conflict()
        time.sleep(1)
        self._pos()
        print('***Calling other nodes to announce theirs***' + "\n")
        time.sleep(1)
        for node in self.nodes:
            node._pos()
        time.sleep(1)
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
            #check index too
            self.blockChain.append(block)
            acct = block['Validator'].rsplit(', ')
            if self.myAccount['Address'] != acct[0]:
                self.myAccount['Age'] += 1
            else:
                self.myAccount['Weight'] += (randint(1, 10) * self.myAccount['Age'])
                self.myAccount['Age'] = 0
        self.tempBlocks = []
        self.myCurrBlock = {}
        self.validators = set()



    def _pos(self):
        print("Coming from ==========================> " + str(self.myAccount) + "\n")
        time.sleep(1)
        print('***Generating new stake block***' + "\n")
        time.sleep(1)
        self.generate_new_block()
        print('***Exchanging temporary blocks with other nodes***' + "\n")
        time.sleep(1)
        self.get_blocks_from_nodes()
        print('***Picking a winner***' + "\n")
        time.sleep(1)
        print("Winner is =======================> " + str(self.pick_winner()) + "\n")
    
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
        return sha256(block_string).hexdigest()

    @staticmethod
    def get_validator(address):
        return ', '.join([address['Address'], str(address['Weight']), str(address['Age'])])

    def generate_genesis_block(self, genesisblock):
        address = {'Address': 'eltneg', 'Weight': 50, 'Age': 0}
        address = self.get_validator(address)
        genesisblock['Index'] = 0 if not genesisblock['Index'] else genesisblock['Index']
        genesisblock['Timestamp'] = str(datetime.now()) if not genesisblock['Timestamp'] else genesisblock['Timestamp']
        genesisblock['BPM'] = 0 if not genesisblock['BPM'] else genesisblock['BPM']
        genesisblock['PrevHash'] = '0000000000000000'
        genesisblock['Validator'] = address if not genesisblock['Validator'] else genesisblock['Validator']
        genesisblock['Hash'] = self.hasher(genesisblock)
        return genesisblock       

def main():
    """Run test"""
    account = {'Address': 'eltneg', 'Weight': 50}
    account2 = {'Address': 'account2', 'Weight': 55}
    account3 = {'Address': 'account3', 'Weight': 43}
    account4 = {'Address': 'account4', 'Weight': 16}
    blockchain = Blockchain(GENESIS_BLOCK, account)
    blockchain.generate_new_block(52)

    blockchain2 = Blockchain(GENESIS_BLOCK2, account2)
    blockchain3 = Blockchain(GENESIS_BLOCK3, account3)

    clients = [blockchain, blockchain2, blockchain3]
    
    blockchain.add_new_node(blockchain2)
    blockchain.add_new_node(blockchain3)

    blockchain2.add_new_node(blockchain)
    blockchain2.add_new_node(blockchain3)

    blockchain.get_blocks_from_nodes()
    blockchain2.get_blocks_from_nodes()

    blockchain.pick_winner()
    #check if temp blocks are same

    blockchain.pos()
    blockchain2.pos()
    blockchain3.pos()

    blockchain4 = Blockchain(GENESIS_BLOCK4, account4)
    blockchain4.add_new_node(blockchain)
    blockchain4.add_new_node(blockchain2)
    blockchain4.add_new_node(blockchain3)
    blockchain4.pos()
    clients.append(blockchain4)
    while True:
        print('============================================ \n\n')
        client = clients[randint(0, 3)]
        client.pos()

if __name__ == '__main__':
    main()