import socket, os
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

class Server:
    def __init__(self, port):
        # get the hostname
        host = socket.gethostname()
        self.server_socket = socket.socket()  # get instance
        # look closely. The bind() function takes tuple as argument
        self.server_socket.bind((host, port))  # bind host address and port together
        self.conn = None
        # RSA
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        # clé AES
        self.cle_aes = os.urandom(32)
        self.iv = os.urandom(16)
    
    def waitForConnection(self):
        # configure how many client the server can listen simultaneously
        self.server_socket.listen(2)
        self.conn, address = self.server_socket.accept()  # accept new connection
        print("Connection from: " + str(address))

    def sendMessage(self, msg: str):
        print("Sending:", msg)
        self.conn.send(str.encode(msg + "@!"))

    def receiveMessage(self):
        msg = self.conn.recv(1024).decode().split("@!")
        return msg

    def sendFile(self, filename: str, encrypt=False):
        print(f"Sending: {filename} (Encrypted: {encrypt})")
        with open(filename, 'rb') as f:
            raw = f.read()
        
        encrypted_data = None
        if encrypt: # AES
            encrypted_data = self.cryptation_AES(raw)
            self.conn.sendall(len(encrypted_data).to_bytes(8, 'big'))
            self.conn.send(encrypted_data)  # => client
            return encrypted_data
        else:
            self.conn.sendall(len(raw).to_bytes(8, 'big'))
            self.conn.send(raw)  # => client
            return raw

    def cryptation_AES(self, data):
        cipher = Cipher(algorithms.AES(self.cle_aes), modes.CBC(self.iv), backend=default_backend())
        crypteur = cipher.encryptor()
        padder = padding.PKCS7(128).padder() # padding (besoin)
        txt_avec_padding = padder.update(data) + padder.finalize()
        donnee_cryptee = crypteur.update(txt_avec_padding) + crypteur.finalize()
        
        return self.iv + donnee_cryptee
    
    def decryptation_AES(self, client_cle_publique_pr):
        client_cle_publique = serialization.load_pem_public_key(
            client_cle_publique_pr.encode(),
            backend=default_backend()
        )
        # AES => clé publ client
        cle_crypte = client_cle_publique.encrypt(
            self.cle_aes,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(cle_crypte).decode()

    def info_txt_hash(self, data): # SHA-3
        infoSAH = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
        infoSAH.update(data)
        return infoSAH.finalize()
    
    def crypte_le_hash(self, txt_hash, client_cle_publique_pr): # hash <=> clé pub client
        cle_pub_client = serialization.load_pem_public_key(
            client_cle_publique_pr.encode(),
            backend=default_backend()
        )
        hash_crypte = cle_pub_client.encrypt(
            txt_hash,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(hash_crypte).decode()

    def fc_get_publicKey(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def close(self):
        if not self.conn == None:
            self.conn.close() # close the connection
        else:
            raise Exception("Erreur: la connexion a été fermée avant d'être instanciée.")
   

if __name__ == '__main__':
    server = Server(5000)
    server.waitForConnection()
    
    server_public_key = server.fc_get_publicKey()    
    server.sendMessage(server_public_key)
    cle_pub_cryptee_client = server.receiveMessage()[0]
    print("client public key reçu")
    f = "input/test.txt"
    txt_decryptee = server.sendFile(filename=f, encrypt=True)    
    
    txt_hash = server.info_txt_hash(txt_decryptee) # calcul hash SHA-3 
    print(f"Hash SHA-3 : {txt_hash.hex()}\n")
    hash_cryptee = server.crypte_le_hash(txt_hash, cle_pub_cryptee_client) # crypté hash (clé publique client)
    # serveur ==AES chiffrée>> client
    crypte_cle_aes = server.decryptation_AES(cle_pub_cryptee_client)
    server.sendMessage(crypte_cle_aes)
    server.sendMessage(hash_cryptee) # envoi du hash chiffré
    
    server.sendMessage("Transmission sécurisée terminée")    
    server.close()