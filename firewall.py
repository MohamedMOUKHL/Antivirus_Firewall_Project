import socket

# Blocklist of IPs to block
blocklist = ["192.168.1.100", "10.0.0.1"]

# Function to monitor connections
def log_to_file(message):
    with open("firewall_logs.txt", "a") as log_file:
        log_file.write(message + "\n")

def monitor_traffic():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 12345)
    print(f"Starting firewall on {server_address[0]}:{server_address[1]}")
    sock.bind(server_address)
    sock.listen(5)
    
    while True:
        print("Waiting for a connection...")
        connection, client_address = sock.accept()
        try:
            print(f"Connection from {client_address}")
            if client_address[0] in blocklist:
                log_to_file(f"Blocked connection from {client_address[0]}")
                connection.close()
            else:
                log_to_file(f"Allowed connection from {client_address[0]}")
                connection.sendall(b"Connection allowed.")
                connection.close()
        except Exception as e:
            log_to_file(f"Error: {e}")
        finally:
            connection.close()
# Start the firewall
monitor_traffic()