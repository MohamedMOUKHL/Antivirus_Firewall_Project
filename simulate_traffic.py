import socket

def simulate_traffic(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        print(f"Connected to {ip}:{port}")
        response = sock.recv(1024)
        print(f"Response: {response.decode()}")
    except Exception as e:
        print(f"Failed to connect to {ip}:{port} - {e}")
    finally:
        sock.close()

# Test traffic to the firewall
simulate_traffic("localhost", 12345)