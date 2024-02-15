import socket, asyncio, hashlib, ssl
from encryption.asymmetric import Asymmetric


API_KEY = Asymmetric.load()
public_key_hash = hashlib.blake2b(
    API_KEY.public_key.export_key(format="DER"), digest_size=64
)
public_key_hash_digest = public_key_hash.digest()


async def handle_client(reader, writer):
    # Get the peer name of the client
    peername = writer.get_extra_info("peername")
    print(f"Accepted connection from {peername}")

    try:
        # Communicate with the client
        encrypted = await reader.read(4096)  # Initial handshake is always 4096 bits.
        decrypted = API_KEY.decrypt(encrypted)
        if decrypted != public_key_hash_digest:
            print("CLIENT WAS MALICIOUS!!")
            writer.close()
            return
        print(f"Received from client: {decrypted}")
        writer.write(decrypted)
        await writer.drain()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Close the SSL/TLS connection
        writer.close()
        print(f"Closed connection from {peername}")


# async def begin_server(HOST="", PORT=10023, certfile="cert.pem", keyfile="key.pem"):
#     # Create a context object with secure settings
#     context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
#     # Load the server certificate and private key
#     context.load_cert_chain(certfile=certfile, keyfile=keyfile)

#     # Set minimum TLS version to TLSv1.2
#     context.minimum_version = ssl.TLSVersion.TLSv1_3

#     # Create a TCP socket object
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     # Bind the socket to a local address and port
#     server.bind((HOST, PORT))
#     # Listen for incoming connections
#     server.listen(10)
#     server.settimeout(5)
#     server.setblocking(False)

#     print(f"Server started on {HOST}:{PORT}")
#     loop = asyncio.get_event_loop()
#     while True:
#         try:
#             # Accept a connection from a client
#             newsocket, fromaddr = await loop.sock_accept(server)
#             loop.create_task(handle_client(context, newsocket, fromaddr))
#         except ssl.SSLError as e:
#             print(f"SSL Error: {e}. Dropping connection and moving to the next client.")
#             continue
#         except Exception as e:
#             print(f"Error: {e}")
#             continue


async def begin_server(HOST="", PORT=10023, certfile="cert.pem", keyfile="key.pem"):
    # Create a context object with secure settings
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    # Load the server certificate and private key
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    # Create a TCP server with SSL
    server = await asyncio.start_server(handle_client, HOST, PORT, ssl=context)
    # Get the server address
    addr = server.sockets[0].getsockname()
    print(f"Server started on {addr}")
    # Serve requests until Ctrl+C is pressed
    async with server:
        await server.serve_forever()


# Example usage:
if __name__ == "__main__":
    asyncio.run(
        begin_server(
            HOST="localhost", PORT=10023, certfile="cert.pem", keyfile="key.pem"
        )
    )
