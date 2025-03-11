import socket, os, base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class Client:
    def __init__(self, port):
        self.host = socket.gethostname()  # as both code is running on same pc
        self.port = port
        self.client_socket = socket.socket()  # instantiate
        self.bfile = None
        # génération RSA
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def connect(self):
        self.client_socket.connect((self.host, self.port))  # connect to the server

    def receiveFile(self, decrypt=False, aes_key=None):
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
        # AES
        if decrypt and aes_key:
            self.bfile = self.decryptation_txt_AES(self.bfile, aes_key)

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

    def decryptation_txt_AES(self, data, aes_key):
        iv = data[:16]
        txt_crypte = data[16:]
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decripteur = cipher.decryptor()
        txt_avec_padding = decripteur.update(txt_crypte) + decripteur.finalize() # décriptation
        unpadder = padding.PKCS7(128).unpadder() # enlever padding
        txt_original = unpadder.update(txt_avec_padding) + unpadder.finalize()
        
        return txt_original
    
    def decrypt_cle_AES(self, encrypted_key_base64):
        cle_crypte = base64.b64decode(encrypted_key_base64)        
        cle_decrypte = self.private_key.decrypt( # décryptation AES avec clé privé client
            cle_crypte,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return cle_decrypte
    
    def fc_get_publicKey(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def close(self):
        if not self.client_socket == None:
            self.client_socket.close()  # close the connection
        else:
            raise Exception("Erreur: la connexion a été fermée avant d'être instanciée.")

if __name__ == '__main__': 
    client = Client(5000)
    client.connect()
    
    server_public_key_pem = client.receiveMessage()[0] # recevoir clé publique server    
    client_public_key_pem = client.fc_get_publicKey() # envoie clé publique au server
    client.sendMessage(client_public_key_pem)
    encrypted_file = client.receiveFile() # recevoir fichier
    encrypted_aes_key_base64 = client.receiveMessage()[0] # recevoir clé privé AES
    aes_key = client.decrypt_cle_AES(encrypted_aes_key_base64) # décryptation fichier AES avec clé client privée
    filename = client.decryptation_txt_AES(encrypted_file, aes_key) # décryptation fichier AES
    output_file = "output/filename.txt" # décrypté
    client.saveFile(bytes=filename, filename=output_file)
    final_message = client.receiveMessage() # message
    print(final_message)

    client.close()
