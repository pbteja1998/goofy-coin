"""This module defines the Goofy Coin System."""

import time

TRX_TYPE_PAY_COINS = "pays"
TRX_TYPE_CREATE_COINS = "creates"

class Node(object):

    """
        All User-related methods are defined in this class
    """

    def __init__(self, username):
        self.username = username
        [self.__private_key, self.public_key] = self.generate_keys()
        self.coins_owned = 0

    def generate_keys(self, bits=2048):
        '''
            Generate an RSA keypair with an exponent of 65537 in PEM format
            param: bits The key length in bits
            Return private key and public key
        '''
        from Crypto.PublicKey import RSA
        new_key = RSA.generate(bits, e=65537)
        public_key = new_key.publickey().exportKey("PEM")
        private_key = new_key.exportKey("PEM")
        return private_key, public_key

    def sign_data(self, hashed_data):
        '''
            param: private_key
            param: hashed_data SHA256 hash of data to be signed
            return: base64 encoded signature
        '''
        from Crypto.PublicKey import RSA
        from Crypto.Signature import PKCS1_v1_5
        from base64 import b64encode
        rsakey = RSA.importKey(self.__private_key)
        signer = PKCS1_v1_5.new(rsakey)
        sign = signer.sign(hashed_data)
        return b64encode(sign)

    def verify_sign(self, signature, hashed_data):
        '''
            Verifies with a public key from whom the data came that it was indeed
            signed by their private key
            param: public_key
            param: signature String signature to be verified
            return: Boolean. True if the signature is valid; False otherwise.
        '''
        from Crypto.PublicKey import RSA
        from Crypto.Signature import PKCS1_v1_5
        from base64 import b64decode
        rsakey = RSA.importKey(self.public_key)
        signer = PKCS1_v1_5.new(rsakey)
        if signer.verify(hashed_data, b64decode(signature)):
            return True
        return False

class Transaction(object):
    """This is the main Transaction class"""

    def __init__(self, trx_id, trx_type, prev_trx, break_trx):
        self.trx_id = str(trx_id)
        self.sender = ""
        self.trx_type = trx_type
        self.trx_value = ""
        self.receiver = ""
        self.trx_timestamp = time.time()
        self.spent = 0
        self.prev_trx = prev_trx
        self.break_trx = break_trx
        self.trx_message = ""
        self.trx_hash = ""
        self.trx_signature = ""

    def set_trx_message(self):
        '''
            param: trx_message
            return: SHA256 encoded hash
        '''
        from base64 import b64encode
        self.trx_message = b64encode(str(self.trx_id) + str(self.sender) + str(self.trx_type) + \
            str(self.trx_value) + str(self.receiver) + str(self.trx_timestamp) + str(self.spent) + \
            str(self.prev_trx) + str(self.break_trx))

    def hash_data(self, data):
        '''
            param: data b64encoded data
            return: SHA256 base64 encoded hash
        '''
        from base64 import b64decode
        from Crypto.Hash import SHA256
        hashed_data = SHA256.new()
        hashed_data.update(b64decode(data))
        return hashed_data

    def create_trx(self, sender_pk, receiver_pk, trx_value):
        '''
            param: sender Public Key of the user who is paying
            param: receiver Public Key of the user who is being paid
            param: trx_value Number of Goofy coins that are being transacted
            param: private_key Private Key of the user who is paying
        '''
        self.sender = sender_pk
        self.receiver = receiver_pk
        self.trx_value = trx_value
        self.set_trx_message()
        self.trx_hash = self.hash_data(self.trx_message)
        return self.trx_hash
        # self.trx_signature = sender.sign_data(self.trx_hash)

    def sign_trx(self, signture):
        """ Sender signs the transaction """
        self.trx_signature = signture

    def verify_sign(self):
        '''
            Verifies with a public key from whom the data came that it was indeed
            signed by their private key
            param: public_key
            param: signature String signature to be verified
            return: Boolean. True if the signature is valid; False otherwise.
        '''
        from Crypto.PublicKey import RSA
        from Crypto.Signature import PKCS1_v1_5
        from base64 import b64decode
        rsakey = RSA.importKey(self.sender)
        signer = PKCS1_v1_5.new(rsakey)
        if signer.verify(self.trx_hash, b64decode(self.trx_signature)):
            return True
        return False

class BlockChain(object):
    """All Goofy Block Chain related methods are in this class"""

    def __init__(self):
        self.nodes = []
        self.goofy = Node("GOOFY")
        self.nodes.append(self.goofy)
        self.ledger = []
        self.latest_trx = ""

    def is_existing_user(self, username):
        '''
            Checks if the user with username alreasy exists
            param: username            
        '''
        for node in self.nodes:
            if node.username == username:
                return 1
        return 0

    def valid_username(self):
        '''
            Takes valid username input
        '''
        print 'username: ',
        username = raw_input()

        while self.is_existing_user(username):
            print "User with username " + username + " already exists. Choose other username."
            print 'username: ',
            username = raw_input()

        return username

    def create_new_node(self):
        '''
            Add a new node in the blockchain network
        '''
        username = self.valid_username()
        new_node = Node(username)
        self.nodes.append(new_node)
        print "Node with username " + username + " created"

    def show_existing_nodes(self):
        '''
            Shows existing nodes in the blockchain
        '''
        for node in self.nodes:
            print node.username
            print str(node.public_key)

    def user_input(self):
        '''
            Takes valid user input
            return: id of the user
        '''
        print " ( ",
        for i in range(0, len(self.nodes)):
            if i == len(self.nodes) - 1:
                print i, " => ", self.nodes[i].username, " ) : ",
            else:
                print i, " => ", self.nodes[i].username, " , ",

        try:
            node = int(input())
            if node < len(self.nodes):
                return node
            else:
                print "INVALID INPUT"
                return

        except:
            print "INVALID INPUT"
            return

    def coinbase_trx(self):
        "Coinbase Transaction"

        trx_type = TRX_TYPE_CREATE_COINS

        trx = Transaction(len(self.ledger), trx_type, len(self.nodes)-1, -1)

        print "number of coins to be created: (input only an integer) : ",
        try:
            number_of_coins = int(input())

        except Exception as e:
            print e
            print "INVALID INPUT"
            return

        trx_hash = trx.create_trx(self.goofy.public_key, self.goofy.public_key, number_of_coins)
        signature = self.goofy.sign_data(trx_hash)
        trx.sign_trx(signature)
        self.ledger.append(trx)
        self.latest_trx = trx
        print str(number_of_coins) + " coins have been created by Goofy"

    def get_trxs_to_break(self, sender, number_of_coins):
        """
            param: sender
            param: number_of_coins
            returns: <list> complete_trx_break List of Transactions that has to be broken completely
            returns: partial_trx_break Transaction Transaction that has to be broken partially
        """

        complete_trx_break = []
        partial_trx_break = -1
        for i in range(len(self.ledger)-1, -1, -1):
            present_trx = self.ledger[i]
            if not present_trx.verify_sign():
                print "MALICIOUS TRANSACTION FOUND"
                return [], -2

            if present_trx.receiver == sender.public_key and not present_trx.spent:
                if number_of_coins >= present_trx.trx_value:
                    complete_trx_break.append(i)
                    number_of_coins -= present_trx.trx_value
                elif number_of_coins < present_trx.trx_value:
                    partial_trx_break = i
                    number_of_coins = 0
                    break

        if number_of_coins == 0:
            return complete_trx_break, partial_trx_break
        return [], -2

    def atomic_payment_trx(self, sender, receiver, number_of_coins, break_trx):
        """ Atomic Transaction => Complete breaking of one trx and complete forming of other trx """

        trx_type = TRX_TYPE_PAY_COINS
        trx = Transaction(len(self.ledger), trx_type, len(self.ledger)-1, break_trx)
        trx_hash = trx.create_trx(sender.public_key, receiver.public_key, number_of_coins)
        signature = sender.sign_data(trx_hash)
        trx.sign_trx(signature)
        self.ledger.append(trx)
        self.latest_trx = trx
        print str(sender.username) + " paid " + \
            str(receiver.username) + " " + str(number_of_coins) + " coins"

    def payment_trx(self):
        "Payment Transaction"
        
        if not self.ledger:
            print "Ledger is empty, You can not make payment transaction"
            return
        
        print "Select Sender",
        sender = self.user_input()
        print "Select Receiver",
        receiver = self.user_input()
        print "number of coins to be sent: (input only an integer) : ",
        try:
            number_of_coins = int(input())
            [complete_trx_break, partial_trx_break] = self.get_trxs_to_break(self.nodes[sender], number_of_coins)

            if partial_trx_break == -2:
                print ""
                print "INVALID TRANSACTION"
                print str(self.nodes[sender].username) + " does not have " + str(number_of_coins) + " number of coins"
                return

            for i in range(0, len(complete_trx_break)):
                present_trx_index = complete_trx_break[i]
                self.atomic_payment_trx(self.nodes[sender], self.nodes[receiver], self.ledger[present_trx_index].trx_value, present_trx_index)
                number_of_coins -= self.ledger[present_trx_index].trx_value
                self.ledger[present_trx_index].spent = 1

            if partial_trx_break >= 0:
                self.atomic_payment_trx(self.nodes[sender], self.nodes[receiver], number_of_coins, partial_trx_break)
                self.atomic_payment_trx(self.nodes[sender], self.nodes[sender], self.ledger[partial_trx_break].trx_value - number_of_coins, partial_trx_break)
                self.ledger[partial_trx_break].spent = 1

        except Exception as e:
            print e
            print "INVALID INPUT"

    def create_transaction(self, trx_type):
        '''
            Create transaction based on the transaction type
        '''
        if trx_type == TRX_TYPE_CREATE_COINS:
            self.coinbase_trx()
        elif trx_type == TRX_TYPE_PAY_COINS:
            self.payment_trx()

    def get_username(self, public_key):
        '''
            param: public_key
            return: username associated with the public_key
        '''
        for node in self.nodes:
            if node.public_key == public_key:
                return node.username

    def show_ledger(self):
        '''
            Show the Ledger in the human understandable format
        '''

        if not self.ledger:
            print "Ledger is empty. Make a transaction"

        for trx in self.ledger:
            
            if trx.spent:
                print "Spent:   ",
            else:
                print "Unspent: ",

            if trx.trx_type == TRX_TYPE_PAY_COINS:
                print "#" + str(trx.trx_id) + " " + str(self.get_username(trx.sender)) + " paid " + \
                    str(self.get_username(trx.receiver)) + " " + str(trx.trx_value) + \
                    " coins at " + str(trx.trx_timestamp) + " -----back_pointer_to----> #" + str(trx.break_trx)

            elif trx.trx_type == TRX_TYPE_CREATE_COINS:
                print "#" + str(trx.trx_id) + " " + str(self.get_username(trx.sender)) + " created " + \
                    str(trx.trx_value) + " coins at " + str(trx.trx_timestamp)

if __name__ == '__main__':
    GOOFY_CHAIN = BlockChain()

    while True:
        # time.sleep(0.5)
        print 'Usage: <option>'
        print '<option> can be 1 => Create New User'
        print '                2 => Create CoinBase Transaction'
        print '                3 => Create Payment Transaction'
        print '                4 => Show Existing Nodes'
        print '                5 => Show Ledger in the human readable format'
        print '                6 => Exit'

        print 'Your Option: ',
        COMMAND = input()
        print ""

        if int(COMMAND) == 1:
            GOOFY_CHAIN.create_new_node()

        elif int(COMMAND) == 2:
            GOOFY_CHAIN.create_transaction(TRX_TYPE_CREATE_COINS)

        elif int(COMMAND) == 3:
            GOOFY_CHAIN.create_transaction(TRX_TYPE_PAY_COINS)

        elif int(COMMAND) == 4:
            GOOFY_CHAIN.show_existing_nodes()

        elif int(COMMAND) == 5:
            GOOFY_CHAIN.show_ledger()

        elif int(COMMAND) == 6:
            break

        else:
            print "INVALID INPUT"

        print ""
        print "----------------------------------------------"
