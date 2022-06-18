import socket
import sys

def calculate_checksum(packet):
    countTo = (len(packet) // 2) * 2

    count = 0
    sum = 0

    while count < countTo:
        if sys.byteorder == "little":
            loByte = packet[count]
            hiByte = packet[count + 1]
        else:
            loByte = packet[count + 1]
            hiByte = packet[count]
        sum = sum + (hiByte * 256 + loByte)
        count += 2

    if countTo < len(packet):
        sum += packet[count]

    sum = (sum >> 16) + (sum & 0xffff)  # adding the higher order 16 bits and lower order 16 bits
    sum += (sum >> 16)
    answer = ~sum & 0xffff
    answer = socket.htons(answer)

    return answer
