import sys
import socket
import random
import threading
import RSA
from Crypto.Cipher import AES
from binascii import a2b_hex, b2a_hex


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
            
        else:
            print('Unrecognized argument: ', sys.argv[1])
            return -1
    return 0


def Server(port, algorithm):
    """
    Creates the server instance, sets it up
    """
    host = 'localhost'
    port = int(port)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)

    # blocking call to accept()
    print('Waiting for partner to join conversation...\n')
    while True:
        (conn, client_addr) = server.accept()
    
        print('Client connected: ', client_addr[0])

        # Geberate public-private key pair
        #e, d, n = RSA.generateKey()
        e = 65537
        n = 74719375368589566905063806760857435673291637842267193500745096668162126326191366618399690384917807545718369894433595432755724733996249641921407631766737112332086370495308840670279944615847024756775958304684827910695812648571842851119141736803294132493235999870118524478867402969989777732224340893519767428411
        d = 52972921216271374141477022956951325719641566886877040627815118581760179371863671928692262605160994430576813409296552246702309204200188399111866011486304005999516004162683496094763316578284099301786733019687955413008741271387390717897510105732807517320933143315352497695701963240766208886214374682223197685049
    
        sendPublic = str(e) + ',' + str(n)
        conn.send(sendPublic.encode('utf-8'))
        print('Public Key sent')
        privateTuple = (d, n)
        
        # Verify WUP Request
        flag = 0
        count = 0
        while count != 129:
            # Decrypt Session Key and WUP request
            print('Number of Trials:', count)

            wup_enc = conn.recv(128)
            encrypted_skey = int(conn.recv(1024).decode('utf-8'))

            print(wup_enc)
            print(len(wup_enc))

            skey = bin(RSA.fastExpMod(encrypted_skey, privateTuple[0], privateTuple[1]))[-128:]
            print('rsa decrypt key is :' , skey)

            skey = int(skey, 2)
            string = ""
            for i in hex(skey)[2:]:
                string += i
            add = 32 - len(string)
            string = '0' * add + string
            print('Session Key is:', string)
            #wup2 = str(AES.new(a2b_hex(hex(skey)[2:]), AES.MODE_ECB).decrypt(wup_enc), 'utf-8')
            print('string is:', string)
            print('string length is:', len(string))
	    #print('wup_enc is:',wup_enc)
	    wup = AES.new(a2b_hex(string[:-1].zfill(32)), AES.MODE_ECB).decrypt(a2b_hex(str(b2a_hex(wup_enc).decode('utf-8'))))
            print('WUP Request is:', wup)
            if verify_wup(wup):
                response = "Valid wup format"
                print('Wup Verified')
                flag = 1
            else:
                response = "xxxxxxxxxxxxxxxx"
                print('Invalid wup format')
                flag = 0
            enc_response = AES.new(a2b_hex(string[:-1].zfill(32)), AES.MODE_ECB).encrypt(response)
            print("Encrypted Response:", enc_response)
            conn.send(enc_response)
            count = count + 1

        print('Type your message below and hit enter to send. Type \'EXIT\' to end conversation.\n')

        ReadThread = Thread_Manager('read', conn, a2b_hex(hex(skey)[2:][:-1]))
        WriteThread = Thread_Manager('write', conn, a2b_hex(hex(skey)[2:][:-1]))

        ReadThread.start()
        WriteThread.start()




    # wait until client dc's
        ReadThread.join()
        print('Your partner has left the conversation. Press any key to continue...\n')

    # stop the write thread
        WriteThread.stopWrite()
        WriteThread.join()

        #
        close = input('please input 1 if you want close:')
        if close == 1:
            break
        else :
            continue

    # shut down client connection
    try:
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
    except:
        # connection already closed
        pass

    # shut down server
    print('Shutting server down...')
    server.shutdown(socket.SHUT_RDWR)
    server.close()

    return 0

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
        
        
#new read        
   # def read(self):
    
   #     while True:
   #         buff = self.conn.recv(1024)
   #         buff = self.decrypt(buff)
   #         while buff.strip() != self.exitcode and len(buff) > 0:
   #             print('Message received: ', buff.strip())
   #             buff = self.conn.recv(1024)
   #             buff = self.decrypt(buff)
   #         # client disconnected
   #         self.stopWrite()
        
        
        
    def encrypt(self, data):
        encrypted_data = AES.new(self.skey, AES.MODE_ECB).encrypt(data)
        return encrypted_data

#new write
    #def write(self):
    
   #     while True:
   #         while self.dowrite:
   #             data = sys.stdin.readline()
   #             if (data.strip() == self.exitcode):
   #                 self.conn.shutdown(socket.SHUT_RDWR)
   #                 self.conn.close()
   #                 self.dowrite = False
   #             else:
   #                 print(len(data.strip()))
   #                  length = len(data.strip())
   #                 if length % 16 != 0:
   #                     pad = 16 - (length % 16)
   #                 else:
   #                     pad = 0
   #                 data = data.strip() + ('\0' * pad)
   #                 data = self.encrypt(data)
   #                 self.conn.send(data)








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

