import bcrypt

def hash_password(password: str) -> bytes:
    """
    Hash a password with a randomly generated salt.
    
    Args:
        password (str): The password to hash.
    
    Returns:
        bytes: The salted, hashed password as a byte string.
    """
    # Generate a salt
    salt = bcrypt.gensalt()
    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validate if a provided password matches the hashed password.
    
    Args:
        hashed_password (bytes): The hashed password.
        password (str): The password to validate.
    
    Returns:
        bool: True if the password matches, False otherwise.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

