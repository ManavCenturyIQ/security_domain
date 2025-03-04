import secrets

# Generate a 32-byte (256-bit) secure key
secret_key = secrets.token_hex(32)
print(secret_key)
