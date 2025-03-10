import socket
import random
from rsa_python import rsa

class Server:
    def __init__(self, port):
        # get the hostname
        host = socket.gethostname()
        self.server_socket = socket.socket()  # get instance
        # look closely. The bind() function takes tuple as argument
        self.server_socket.bind((host, port))  # bind host address and port together
        self.conn = None

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

    def sendFile(self, filename: str):
        print("Sending:", filename)
        with open(filename, 'rb') as f:
            raw = f.read()
        # Send actual length ahead of data, with fixed byteorder and size
        self.conn.sendall(len(raw).to_bytes(8, 'big'))
        self.conn.send(raw)  # send data to the client


    def close(self):
        if not self.conn == None:
            self.conn.close()  # close the connection
        else:
            raise Exception("Erreur: la connexion a été fermée avant d'être instanciée.")


# Retourne le pgcd de a et b
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Génération et retourne un nombre premier
def generate_random_prime():
    isPrime = False
    # On boucle tant que nous n'avons pas de nombre premier
    while not isPrime:
        # Sélectionne un nombre aléatoire compris entre 1000 et 1,000,000
        x = random.randrange(pow(10,3), pow(10,6), 1)
        # Le flag passe à vrai quand le nombre n'est pas premier
        flag = False
        # La boucle s'arrête lorsque le nombre n'est pas premier (flag devient True) ou s'il est premier (isPrime devient True)
        while not flag and not isPrime:
            # Cherche des facteurs
            for i in range(2, x):
                if (x % i) == 0:
                    flag = True
                    break
            if not flag:
                isPrime = True
    return x

# Génération de e en fonction de phi
def generate_e(phi):
    flag = False
    # On boucle tant que e n'est aps premier avec phi
    while not flag:
        # Sélectionne un nombre aléatoire compris entre 100 et phi
        e = random.randint(100, phi)
        if gcd(e, phi) == 1:
            flag = True
    return e

# Algorithme d'Euclide étendu
# a est le nombre dont on veut connaître l'inverse
# b est la taille de l'ensemble Z/bZ (phi dans le cas de cet algo)
# x et y sont respectivement un des coefficients de bézout et le même coefficient à l'étape n-1
# Algo décrit ici: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
def egcd(a, b, x = 0, y = 1):
    x, y = y, x - (b // a) * y
    # Si le reste de b//a est 0, alors on a fini
    if b % a == 0:
        return x, y
    # A chaque nouvelle étape, on rappelle egcd() avec a = b % a et b = a
    # -> Comme dans l'algorithme d'Euclique que l'on a vu en CM
    return egcd(b % a, a, x, y)

# Génère les clés privées et publiques et les retourne dans un dictionnaire
def generate_key_pair():
    # Génère deux nombres premiers p et q
    p, q = generate_random_prime(), generate_random_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = generate_e(phi)
    d = egcd(e, phi)[0]
    # Si l'inverse de e (d) est d < 0 ou d > phi, le remettre dans l'intervalle [0, phi-1]
    d %= phi
    keys = {
        "p": p,
        "q": q,
        "phi": phi,
        "public": e,
        "private": d,
        "modulus": n
    }
    return keys

# Liste de caractères dans l'alphabet
chars = [char for char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`1234567890-=~!@#$%^&*()_+[]\\{}|;':,./<>? "]

def encrypt(m, e, n):
    c = []
    # chars.index(m[i]) -> index dans l'alphabet l81
    for i in range(len(m)):
        # Cette opération est celle décrite dans le CM2, elle chiffre une lettre du message complet
        c.append(pow(chars.index(m[i]), e, n))
    # Chaque lettre chiffrée est séparée d'un tiret
    return "-".join([str(num) for num in c])

def decrypt(c, d, n):
    m = []
    # On re-sépare les caractères chiffrés en splittant sur le tiret
    for i in c.split("-"):
        # On les déchiffre avec l'équation présentée dans le CM2
        m.append(chars[pow(int(i), d, n)])
    # Et on re-colle le message
    return "".join(m)


if __name__ == '__main__':
    server = Server(5000)
    server.waitForConnection()
    f = "input/test.txt"
    server.sendFile(filename=f)


    server_keys = generate_key_pair()
    
    # échange
    server.sendMessage(server_keys['public'])
    client_public_key = server.receiveMessage()

    # server clé public => client
    server.sendMessage(server_keys['public'])
    server_public_key = server.receiveMessage()

    server.sendMessage("Ce message a bien été transmis du serveur au client1")
    server.sendMessage("Ce message a bien été transmis du serveur au client2")
    server.sendMessage("Ce message a bien été transmis du serveur au client3")
    server.sendMessage("Ce message a bien été transmis du serveur au client4")
    server.sendMessage("Ce message a bien été transmis du serveur au client5")
    server.close()