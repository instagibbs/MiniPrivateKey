import hashlib
import base58
import ecdsa


def mini_key_to_wif(mini_key):
    # Validate mini key
    if not mini_key.startswith('S'):
        raise ValueError("Invalid mini key format")

    # Check mini key validity by appending '?' and ensuring SHA-256 starts with 0x00
    test_key = mini_key + '?'
    if hashlib.sha256(test_key.encode('utf-8')).digest()[0] != 0x00:
        raise ValueError("Invalid mini key checksum")

    # Generate full private key using SHA-256
    full_key = hashlib.sha256(mini_key.encode('utf-8')).hexdigest()

    # Convert full key to WIF
    extended_key = '80' + full_key
    first_hash = hashlib.sha256(bytes.fromhex(extended_key)).digest()
    second_hash = hashlib.sha256(first_hash).digest()
    checksum = second_hash[:4]
    final_key = bytes.fromhex(extended_key) + checksum
    wif_key = base58.b58encode(final_key).decode('utf-8')

    return wif_key


def mini_key_to_address(mini_key):
    # Validate mini key
    if not mini_key.startswith('S'):
        raise ValueError("Invalid mini key format")

    # Check mini key validity by appending '?' and ensuring SHA-256 starts with 0x00
    test_key = mini_key + '?'
    if hashlib.sha256(test_key.encode('utf-8')).digest()[0] != 0x00:
        raise ValueError("Invalid mini key checksum")

    # Generate full private key using SHA-256
    full_key = hashlib.sha256(mini_key.encode('utf-8')).digest()

    # Generate public key
    sk = ecdsa.SigningKey.from_string(full_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key

    # Uncompressed public key
    public_key = b'\x04' + vk.to_string()

    # Hash public key (RIPEMD-160 of SHA-256)
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    hashed_public_key = ripemd160.digest()

    # Add version byte (0x00 for mainnet)
    extended_key = b'\x00' + hashed_public_key

    # Double SHA-256 for checksum
    first_hash = hashlib.sha256(extended_key).digest()
    second_hash = hashlib.sha256(first_hash).digest()
    checksum = second_hash[:4]

    # Encode address in Base58
    address = base58.b58encode(extended_key + checksum).decode('utf-8')

    return address


# Example Usage, key from https://en.bitcoin.it/wiki/Mini_private_key_format
mini_key = 'S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy'  # Replace with your mini private key
wif_key = mini_key_to_wif(mini_key)
address = mini_key_to_address(mini_key)

print("WIF Key:", wif_key)
print("Address:", address)

