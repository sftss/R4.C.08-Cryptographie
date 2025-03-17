import socket, os, base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms 
from cryptography.hazmat.backends import default_backend

class Client:
    def __init__(self, port):
        self.host = socket.gethostname()  # as both code is running on same pc
        self.port = port
        self.client_socket = socket.socket()  # instantiate
        self.bfile = None
        self.private_key = rsa.generate_private_key( # RSA
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
        return self.bfile

    def receiveMessage(self):
        msg = self.client_socket.recv(1024).decode().split("@!")
        return msg

    def sendMessage(self, msg: str):
        print("Sending:", msg)
        self.client_socket.send(str.encode(msg + "@!"))

    def saveFile(self, data, filename: str):
        with open(filename, 'wb') as f:
            f.write(data)

    def decryptation_txt_AES(self, data, aes_key):
        iv = data[:16]
        txt_crypte = data[16:]
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decripteur = cipher.decryptor()
        txt_avec_padding = decripteur.update(txt_crypte) + decripteur.finalize() # décriptation
        unpadder = padding.PKCS7(128).unpadder() # -- padding
        txt_original = unpadder.update(txt_avec_padding) + unpadder.finalize()
        
        return txt_original
    
    def decrypt_cle_AES(self, encrypted_key_base64):
        cle_crypte = base64.b64decode(encrypted_key_base64)        
        cle_decrypte = self.private_key.decrypt( 
            cle_crypte,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return cle_decrypte
    
    def decrypt_hash(self, hash_crypte):
        hash_cryptee = base64.b64decode(hash_crypte)
        donnee_hash = self.private_key.decrypt(
            hash_cryptee,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return donnee_hash
    
    def info_txt_hash(self, txt): # SHA-3
        infoSAH = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
        infoSAH.update(txt)
        return infoSAH.finalize()
    
    def verif_txt(self, data_txt, hash_normal): # hash
        hash = self.info_txt_hash(data_txt)
        return hash == hash_normal
    
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
    serveur_cle_publique = client.receiveMessage()[0]  
    client_cle_publique = client.fc_get_publicKey() 
    client.sendMessage(client_cle_publique)
    txt_cryptee = client.receiveFile()
    # AES chiffré
    crypte_aes = client.receiveMessage()[0]
    cle_aes = client.decrypt_cle_AES(crypte_aes)
    print("clé AES décryptée")
    # hash chiffré
    crypte_hash = client.receiveMessage()[0]
    hash_normal = client.decrypt_hash(crypte_hash)
    print(f"Teste hash (SHA-3): {hash_normal.hex()}")
    # intégrité
    exactitude_txt = client.verif_txt(txt_cryptee, hash_normal)
    if exactitude_txt: print("Message pas corrompu 😇😎😋😜😝")
    else: raise Exception("Message corrommpu 👿🧛‍♀️👹👺")
    # déchiffrement AES
    txt_decryptee = client.decryptation_txt_AES(txt_cryptee, cle_aes)
    f = "output/filename.txt"
    client.saveFile(txt_decryptee, f)
    print("Message décrypté : ", txt_decryptee)

    client.close()