import os
import math


def read_integer_from_console(prompt):
    try:
        return int(input(prompt))
    except ValueError:
        print("Invalid input. Please enter an integer.")
        return read_integer_from_console(prompt)


def read_string_from_console(prompt):
    return input(prompt)


def save_to_file(file_name, data):
    with open(file_name, "w") as file:
        file.write(data)


def read_from_file(file_name):
    with open(file_name, "r") as file:
        return file.read()


def factorize(n):
    x = 2
    y = 2
    d = 1

    while d == 1:
        x = f(x) % n
        y = f(f(y)) % n
        d = math.gcd(abs(x - y), n)

    return d, n // d


def f(x):
    return x ** 2 + 1


def main():
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789 "

    choice = read_string_from_console("Select 1 for encryption or 2 for decryption: ")
    if choice == "1":
        p = read_integer_from_console("Enter a prime number p: ")
        q = read_integer_from_console("Enter a prime number q: ")
        x = read_string_from_console("Enter open text x: ").lower()

        n = p * q
        phi = (p - 1) * (q - 1)

        e = 3
        while math.gcd(phi, e) != 1:
            e += 2

        d = pow(e, -1, phi)

        encrypt_text = ""
        for char in x:
            index = alphabet.index(char) + 1
            result = pow(index, e, n)
            encrypt_text += str(result) + " "

        save_to_file("encrypted_text.txt", encrypt_text.strip())
        save_to_file("public_key.txt", f"{e},{n}")
        save_to_file("private_key.txt", f"{d},{n}")

        print("Ciphertext:", encrypt_text.strip())

    elif choice == "2":
        encrypted_text = read_from_file("encrypted_text.txt").strip()
        public_key = read_from_file("public_key.txt").strip().split(",")
        private_key = read_from_file("private_key.txt").strip().split(",")

        decrypt_text = ""
        for number in encrypted_text.split():
            result = pow(int(number), int(private_key[0]), int(private_key[1]))
            index = (result - 1) % len(alphabet)
            decrypt_text += alphabet[index]

        print("Decrypted text:", decrypt_text.strip())
        print("Public Key:", f"{public_key[1]},{public_key[0]}")
        print("Private Key:", f"{private_key[1]},{private_key[0]}")

        n = int(public_key[1])
        d = int(private_key[0])
        factors = factorize(n)
        p, q = factors
        if p is not None and q is not None:
            print("p:", p)
            print("q:", q)
        else:
            print("Unable to determine p and q from d and n.")


if __name__ == "__main__":
    main()
