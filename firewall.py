import socket
import os

# Function to load blocklist from file
def load_blocklist():
    if not os.path.exists("blocklist.txt"):
        return []
    with open("blocklist.txt", "r") as f:
        return f.read().splitlines()

# Function to log messages to file and console
def log_to_file(message):
    print(message)  # Print to console
    with open("firewall_logs.txt", "a") as log_file:
        log_file.write(message + "\n")

# Function to monitor TCP traffic
def monitor_traffic():
    # Load the blocklist
    blocklist = load_blocklist()
    log_to_file(f"Blocklist loaded: {blocklist}")

    # Create a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Bind the socket to all interfaces and a specific port
    server_address = ('0.0.0.0', 12345)
    log_to_file(f"Starting firewall on {server_address[0]}:{server_address[1]}")
    sock.bind(server_address)
    
    # Listen for incoming connections
    sock.listen(5)
    log_to_file("Firewall is running. Waiting for connections...")

    try:
        while True:
            # Accept a connection
            connection, client_address = sock.accept()
            src_ip = client_address[0]
            log_to_file(f"Connection from {src_ip}")

            # Check if the IP is in the blocklist
            if src_ip in blocklist:
                log_to_file(f"Blocked connection from {src_ip}")
                connection.close()
            else:
                log_to_file(f"Allowed connection from {src_ip}")
                connection.sendall(b"Connection allowed.")
                connection.close()
    except KeyboardInterrupt:
        log_to_file("Firewall stopped by user.")
    except Exception as e:
        log_to_file(f"Error: {e}")
    finally:
        # Close the socket
        sock.close()
        log_to_file("Firewall socket closed.")

# Start the firewall
if __name__ == "__main__":
    monitor_traffic()