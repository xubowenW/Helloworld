#! /usr/bin/python
#coding=utf-8
#
# ServerClient.py - 2-way Chat Server with textbook/oaep RSA-AES encryption.
#                   Cracker is able to crack the AES session key through CCA2 method.



import sys
import socket
import threading
import RSA
from Crypto.Cipher import AES
from binascii import a2b_hex, b2a_hex
import random

def main():
    """
    Main - Checks for correct input arguments and runs the appropriate methods
    """

    if len(sys.argv) < 4:
        print('Usage: python ServerClient.py <server|client|crack> <port> <algorithm>\n')
        return -1
    else:
        alg = 0
        if sys.argv[3].lower() == 'oaep':
            alg = 1
        elif sys.argv[3].lower() == 'rsa':
            alg = 0

        if sys.argv[1].lower() == 'server':
            Server(sys.argv[2], alg)
        elif sys.argv[1].lower() == 'client':
            Client(sys.argv[2], alg)
        elif sys.argv[1].lower() == 'cracker':
            Cracker(sys.argv[2], alg)
        else:
            print('Unrecognized argument: ', sys.argv[1])
            return -1
    return 0

def Cracker(port, algorithm):
    """
    Creates the cracker instance, sets up the cracker
    """

    host = 'localhost'
    port = int(port)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    # Receive Server's Public Key
    key = client.recv(2048).decode('utf-8')
    key = key.split(',')
    keyTuple = (int(key[0]), int(key[1]))
    print('Server\'s Public Key received:', keyTuple)

    wup_request = "network_security"
    skey = 0
    while skey % 2 == 0:
        skey = random.randrange(1 << 127, 2 ** 128)
    enc_skey = RSA.endecrypt(skey, keyTuple[0], keyTuple[1])

    print(enc_skey)
    print(type(enc_skey))

    #input the enc_skey you got
    skey_get = int('11110111100000001100111101100111010100010100000110001000011110000000010000101111100110111111011100101001100010100000011111101101',2)


    

    #print(skey_get)
    #print(type(skey_get))
    
    enc_skey_get = 21335312826344238299201741404060026176140496948109958857584271470430601771935266950882197674531058549365545724496937981731299575715459600911449872927307521880755616196973691259069344464859392032782044082641046195093403091417574838315226077375197499275031494587276350543652620878981365567539080379524861860211

    print(enc_skey_get)
    print(type(enc_skey_get))


    # Start Cracking
    cur_skey = 0
    for i in range(128, 0, -1):
        if i == 128:
            encrypted_wup = AES.new(a2b_hex(hex(skey)[2:][:-1]), AES.MODE_ECB).encrypt(wup_request)
            send_content1 = encrypted_wup
            send_content2 = str(enc_skey)

            client.send(send_content1)
           # print('Encrypted Wup Sent:', encrypted_wup)
            client.send(send_content2.encode('utf-8'))
           # print('Session Key Sent:', send_content2)

            response_enc = client.recv(1024)
            response = AES.new(a2b_hex(hex(skey)[2:][:-1]), AES.MODE_ECB).decrypt(a2b_hex(str(b2a_hex(response_enc).decode('utf-8'))))
            #print('Response:', response)


        print('Number of trials:', 129 - i)

        #Send Encrypted Session Key and WUP Request
        cur_skey_test = int(cur_skey >> 1) + (1 << 127)
        print("k" + str(i - 1), ": ", bin(cur_skey_test)[2:])
        fac = RSA.fastExpMod(2, (i - 1) * keyTuple[0], keyTuple[1])
        #change enc_skey to enc_skey_get
        enc_cur_skey_test = RSA.fastExpMod(enc_skey_get * fac, 1, keyTuple[1])
        encrypted_wup = AES.new(a2b_hex(hex(cur_skey_test)[2:][:-1]), AES.MODE_ECB).encrypt(wup_request)

        send_content1 = encrypted_wup
        send_content2 = str(enc_cur_skey_test)

        client.send(send_content1)
        #print('Encrypted Wup Sent:', encrypted_wup)
        client.send(send_content2.encode('utf-8'))
        #print('Session Key Sent:', send_content2)

        # Get response from the server
        response_enc = client.recv(1024)
        response = AES.new(a2b_hex(hex(cur_skey_test)[2:][:-1]), AES.MODE_ECB).decrypt(a2b_hex(str(b2a_hex(response_enc).decode('utf-8'))))
        print(response_enc)
        print(type(response_enc))

        # print('Response:', response)
        if response == b"Valid wup format":
            cur_skey = cur_skey_test
        else:
            cur_skey_test = int(cur_skey >> 1)
            cur_skey = cur_skey_test

    if skey_get == cur_skey:
        print('Successfully cracked.')
    else:
        print('Crack failed.')

    #print('True Session Key:', skey_get)
    #print('Cracked Session Key:', cur_skey)



    # this is the package that client send to server : hello or hi
    pack = "9473b119d6c9f02c18f8ad856f456a7b"
    message = AES.new(a2b_hex(hex(cur_skey)[2:][:-1]), AES.MODE_ECB).decrypt(a2b_hex(str(pack).decode('utf-8')))
    print(message)


    print('Type your message below and hit enter to send. Type \'EXIT\' to end conversation.\n')
    ReadThread = Thread_Manager('read', client, a2b_hex(hex(cur_skey)[2:][:-1]))
    WriteThread = Thread_Manager('write', client, a2b_hex(hex(cur_skey)[2:][:-1]))

    ReadThread.start()
    WriteThread.start()

    ReadThread.join()
    print('Your partner has left the conversation. Press any key to continue...\n')

    # stop the write thread
    WriteThread.stopWrite()
    WriteThread.join()

    # shut down client connection
    try:
        client.shutdown(socket.SHUT_RDWR)
        client.close()
    except:
        # connection already killed
        pass


def verify_wup(wup):
    return wup == b"network_security"


class Thread_Manager(threading.Thread):
    """
    Creates threads for asynchronoues reading and writing
    """

    def __init__(self, action, conn, skey):
        """
        Constructor for Thread_Manager class
        """

        threading.Thread.__init__(self)
        self.action = action.lower()
        self.conn = conn
        self.dowrite = True
        self.exitcode = 'EXIT'
        self.skey = skey

    def run(self):
        """
        Invoked when new thread is executed
        """

        if (self.action == 'read'):
            self.read()
        else:
            self.write()

    def stopWrite(self):
        """
        Terminates the write loop
        """

        self.dowrite = False

    def decrypt(self, buff):
        """
        Decrypts input integer list into sentences
        """

        decrypted_data = AES.new(self.skey, AES.MODE_ECB).decrypt(buff)
        return decrypted_data

    def read(self):
        """
        Responsible for reading in data from the client and displaying stdout
        """

        buff = self.conn.recv(1024)
        buff = self.decrypt(buff)
        while buff.strip() != self.exitcode and len(buff) > 0:
            print('Message received: ', buff.strip())
            buff = self.conn.recv(1024)
            buff = self.decrypt(buff)
        # client disconnected
        self.stopWrite()

    def encrypt(self, data):
        encrypted_data = AES.new(self.skey, AES.MODE_ECB).encrypt(data)
        return encrypted_data

    def write(self):
        """
        Responsible for reading in data from stdin and sending to client
        """

        while self.dowrite:
            data = sys.stdin.readline()
            if (data.strip() == self.exitcode):
                self.conn.shutdown(socket.SHUT_RDWR)
                self.conn.close()
                self.dowrite = False
            else:
                print(len(data.strip()))
                length = len(data.strip())
                if length % 16 != 0:
                    pad = 16 - (length % 16)
                else:
                    pad = 0
                data = data.strip() + ('\0' * pad)
                data = self.encrypt(data)
                self.conn.send(data)


# Entry point
if __name__ == "__main__":
    sys.exit(main())
