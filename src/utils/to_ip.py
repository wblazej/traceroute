import socket

def is_ip_valid(hostname):
    ip_parts = hostname.strip().split('.')
    if len(ip_parts) != 4:
        return False

    for part in ip_parts:
        try:
            if int(part) < 0 or int(part) > 255:
                return False
        except ValueError:
            return False

    return True

def to_ip(hostname):
    if is_ip_valid(hostname):
        return hostname
    return socket.gethostbyname(hostname)
    