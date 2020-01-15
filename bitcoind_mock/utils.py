import random


def get_random_value_hex(nbytes):
    """
    Returns a pseduorandom hex value of a fixed length

    Args:
        nbytes (:obj:`int`): integer number of random hex-encoded bytes to return.


    Returns:
        (:obj:`str`): A pseduorandom hex string representing `nbytes` bytes.
    """
    pseudo_random_value = random.getrandbits(8 * nbytes)

    # left 0-pad, to 2*nbytes characters, lower-case hex
    return f"{pseudo_random_value:0{2*nbytes}x}"
