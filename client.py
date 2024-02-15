# Import socket and ssl modules
import socket, random, hashlib, ssl
from encryption.asymmetric import Asymmetric
from bitarray import bitarray


# Create an SSL context with secure settings
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="cert.pem")
context.minimum_version = ssl.TLSVersion.TLSv1_3
# Server address and port
server_address = ("localhost", 10023)
API_KEY = Asymmetric.load()
public_key_hash = hashlib.blake2b(
    API_KEY.public_key.export_key(format="DER"), digest_size=64
)
public_key_hash_digest = public_key_hash.digest()
encrypted = API_KEY.encrypt(public_key_hash_digest)


# Create a TCP socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the server's address and port
client_socket.connect(server_address)

# Wrap the socket with SSL/TLS
ssl_socket = context.wrap_socket(client_socket, server_hostname=server_address[0])

# Communicate with the server by sending and receiving data
ssl_socket.send(encrypted)
data = ssl_socket.recv(1024)
print("Received from server:", data.decode())

# Close the connection
ssl_socket.close()
