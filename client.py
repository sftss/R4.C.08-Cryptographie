import socket, os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class Client:

    def __init__(self, port):
        self.host = socket.gethostname()  # as both code is running on same pc
        self.port = port
        self.client_socket = socket.socket()  # instantiate
        self.bfile = None

    def connect(self):
        self.client_socket.connect((self.host, self.port))  # connect to the server

    def receiveFile(self):
        # receive the size of the file
        expected_size = b""
        while len(expected_size) < 8:
            more_size = self.client_socket.recv(8 - len(expected_size))
            if not more_size:
                raise Exception("Short file length received")
            expected_size += more_size

        # Convert to int, the expected file length
        expected_size = int.from_bytes(expected_size, 'big')

        # Until we've received the expected amount of data, keep receiving
        self.bfile = b""  # Use bytes, not str, to accumulate
        while len(self.bfile) < expected_size:
            buffer = self.client_socket.recv(expected_size - len(self.bfile))
            if not buffer:
                raise Exception("Incomplete file received")
            self.bfile += buffer
        return self.bfile

    def receiveMessage(self):
        msg = self.client_socket.recv(1024).decode().split("@!")
        return msg

    def sendMessage(self, msg: str):
        print("Sending:", msg)
        self.client_socket.send(str.encode(msg + "@!"))

    def saveFile(self, bytes: b"", filename: str):
        with open(filename, 'wb') as f:
            f.write(self.bfile)

    def close(self):
        if not self.client_socket == None:
            self.client_socket.close()  # close the connection
        else:
            raise Exception("Erreur: la connexion a été fermée avant d'être instanciée.")

#region RSA
cle_privee = rsa.generate_private_key(public_exponent=65537, key_size=2048)
cli_public_key = cle_privee.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

public_key_fich = open("output/filename.txt", "w")
public_key_fich.write(cli_public_key.decode())
public_key_fich.close()
#endregion RSA

if __name__ == '__main__': 
    client = Client(5000)
    client.connect()
    bfile = client.receiveFile()
    f = "output/filename.txt"
    client.saveFile(bytes=bfile, filename=f)
    msg = client.receiveMessage()
    ciphertext_aes_key = client.receiveMessage()
    print(msg)
    client.sendMessage(cli_public_key.decode())
    client.close()
    
#region AES
aes_key = os.urandom(32)  #256 bits

# client_private_key = rsa.load_pem_private_key(cle_privee, password=None, backend=default_backend())

# #décryptation
# decrypted_aes_key = client_private_key.decrypt(
#     ciphertext_aes_key,
#     rsa.OAEP(
#         mgf= rsa.mgf1(algorithm=hashes.SHA256()),
#         algorithm=hashes.SHA256(),
#         label=None
#     )
# )

#endregion AES
