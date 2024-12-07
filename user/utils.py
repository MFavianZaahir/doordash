import secrets

def random_hex(length=6):
    """
    Generate a random hexadecimal string of the given length.
    For example, random_hex(6) might return 'a3f4b9'.
    """
    return secrets.token_hex(length // 2)

# You can add more utility functions here as needed.
