def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extended_gcd(b % a, a)
        return g, x - (b // a) * y, y

def mod_inverse(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def generate_keypair(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # constant
    d = mod_inverse(e, phi)
    return ((n, e), (n, d))

def encrypt(pk, plaintext):
    n, e = pk
    cipher = [pow(ord(char), e, n) for char in plaintext]
    return cipher

def decrypt(pk, ciphertext):
    n, d = pk
    plain = [chr(pow(char, d, n)) for char in ciphertext]
    return ''.join(plain)

def save_keys(filename, public_key, encrypted_text):
    with open(filename, 'w') as file:
        file.write(f"{public_key[0]},{public_key[1]}\n")
        file.write(str(encrypted_text))
        
p = int(input("Enter p: "))
q = int(input("Enter q: "))
x = input("Enter plaintext x: ")

public_key, private_key = generate_keypair(p, q)

encrypted_text = encrypt(public_key, x)

save_keys("keys.txt", public_key, encrypted_text)
print("Saved to file")

decrypted_text = decrypt(private_key, encrypted_text)

# print("Public Key (n, e):", public_key)
# print("Private Key (n, d):", private_key)
print("Encrypted Text:", encrypted_text)
print("Decrypted Text:", decrypted_text)
