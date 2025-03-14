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
        # génération RSA
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        # clé AES
        self.aes_key = os.urandom(32)
        self.iv = os.urandom(16)  # iv => vecteur d'initialisation
    
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
        
        if encrypt: # AES
            raw = self.cryptation_AES(raw)
            
        self.conn.sendall(len(raw).to_bytes(8, 'big'))
        self.conn.send(raw)  # send data to the client

    def cryptation_AES(self, data):
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(self.iv), backend=default_backend())
        crypteur = cipher.encryptor()
        # padding
        padder = padding.PKCS7(128).padder()
        txt_avec_padding = padder.update(data) + padder.finalize()
        encrypted_data = crypteur.update(txt_avec_padding) + crypteur.finalize()
        
        return self.iv + encrypted_data
    
    def decryptation_AES(self, client_public_key_pem):
        # cé publique du client
        client_public_key = serialization.load_pem_public_key(
            client_public_key_pem.encode(),
            backend=default_backend()
        )
        # AES => clé publique du client
        cle_crypte = client_public_key.encrypt(
            self.aes_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(cle_crypte).decode()

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
    server.sendMessage(server_public_key) # envoi clé publique du server
    client_public_key_cryp = server.receiveMessage()[0] # reception clé publique du client
    print("Received client public key")
    f = "input/test.txt"
    server.sendFile(filename=f, encrypt=True) # envoi fichier crypté    
    crypte_cle_aes = server.decryptation_AES(client_public_key_cryp)
    server.sendMessage(crypte_cle_aes) # envoi clé AES cryptée (avec clé publique du client)
    
    server.sendMessage("Transmission sécurisée terminée")    
    server.close()