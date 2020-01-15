import random

from hashlib import sha256
from binascii import unhexlify, hexlify


def get_random_value_hex(nbytes):
    """ Returns a pseduorandom hex value of a fixed length
    :param nbytes: Integer number of random hex-encoded bytes to return
    :type nbytes: int
    :return: A pseduorandom hex string representing `nbytes` bytes
    :rtype: hex str
    """
    pseudo_random_value = random.getrandbits(8 * nbytes)

    # left 0-pad, to 2*nbytes characters, lower-case hex
    return f"{pseudo_random_value:0{2*nbytes}x}"
