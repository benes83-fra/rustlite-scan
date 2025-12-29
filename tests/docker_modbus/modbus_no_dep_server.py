import socket
import threading

HOST = "0.0.0.0"
PORT = 5020

# Server ID bytes (vendor string)
SERVER_ID = b"RustLite Test Device"

def handle_client(conn):
    try:
        while True:
            req = conn.recv(1024)
            if not req:
                break

            # Minimal Modbus/TCP header parsing
            if len(req) < 8:
                break

            transaction_id = req[0:2]
            protocol_id = req[2:4]
            length = req[4:6]
            unit_id = req[6]
            function = req[7]

            # Only respond to Function 0x11 (Report Server ID)
            if function == 0x11:
                byte_count = len(SERVER_ID)
                response_pdu = bytes([0x11, byte_count]) + SERVER_ID

                # MBAP header
                response = (
                    transaction_id +
                    b"\x00\x00" +  # Protocol ID
                    bytes([0x00, len(response_pdu) + 1]) +  # Length
                    bytes([unit_id]) +
                    response_pdu
                )

                conn.sendall(response)
            else:
                # Ignore unsupported functions
                pass

    finally:
        conn.close()


def start_server():
    print(f"Starting Modbus/TCP server on port {PORT}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen()

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    start_server()

