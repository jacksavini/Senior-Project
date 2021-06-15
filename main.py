'''
This is the code from my Final Senior Presentation at University.
I created a series of functions which allow the user to encrypt and
decrypt code using the Khan and Shah cipher method.
I used the numpy package for this project, due to the cipher's basis
in linear algebraic principles. Matrix calculations were necessary.

Here is a link to my presentation on matrix ciphers, in which I use this code.
https://www.youtube.com/watch?v=OME661sWCJ0

Authored by Jack Savini
'''

import random as r
import numpy as np


def mod_matrix_inverse(mat, mod):
    # numpy did not have any methods for modular matrix inverse calculations,
    # so I made one myself.
    # The mod_matrix_inverse function finds the modular inverse of a 2x2 matrix and returns it.

    # Inputs:
    # mat - The matrix to find the inverse of
    # mod - The modular base

    # Output:
    # If the matrix is invertible, this function returns its modular inverse.
    # If the matrix is not invertible, it returns "error" as a string.

    left_arr = 1
    right_arr = 1

    for i in range(mod):
        for ii in range(mod):

            if (i * mat[0][0] + ii * mat[0][1]) % mod == 1 and (i * mat[1][0] + ii * mat[1][1]) % mod == 0:
                left_arr = np.array([i, ii])

            if (i * mat[0][0] + ii * mat[0][1]) % mod == 0 and (i * mat[1][0] + ii * mat[1][1]) % mod == 1:
                right_arr = np.array([i, ii])

    if type(left_arr) != int and type(right_arr) != int:
        return np.array([[left_arr[0], right_arr[0]], [left_arr[1], right_arr[1]]])

    return "error"


def mod_num_inverse(num, mod):
    # The mod_num_inverse function finds the modular inverse of an integer.

    # Inputs:
    # num - The integer to find the modular inverse of
    # mod - The modular base

    # Output:
    # If the integer is invertible, this function returns its modular inverse.
    # If the integer is not invertible, it returns "error" as a string.

    for i in range(mod):
        if (num * i) % mod == 1:
            return i

    return "error"


def get_keys():

    # The K&S cipher has a public/private key system.
    # The function get_keys returns a predetermined private key,
    # and its corresponding public key. It also prints them
    # to the console, for the purposes of the presentation attached
    # to this code.

    mod = 95

    A = np.array([[14, 13], [13, 14]])
    B = np.array([[12, 11], [11, 12]])
    N = np.array([[14, 15], [43, 58]])

    A_inv = mod_matrix_inverse(A, mod)
    B_inv = mod_matrix_inverse(B, mod)
    N_inv = mod_matrix_inverse(N, mod)

    priv_key = []
    priv_key.append(A)
    priv_key.append(B)

    key1 = np.mod(np.dot(A_inv, A_inv), mod)
    key1 = np.mod(np.dot(key1, B_inv), mod)
    key1 = np.mod(np.dot(key1, N), mod)
    key1 = np.mod(np.dot(key1, A), mod)
    key1 = np.mod(np.dot(key1, A), mod)
    key1 = np.mod(np.dot(key1, B), mod)

    key2 = np.mod(np.dot(A_inv, B_inv), mod)
    key2 = np.mod(np.dot(key2, B_inv), mod)
    key2 = np.mod(np.dot(key2, N_inv), mod)
    key2 = np.mod(np.dot(key2, A), mod)
    key2 = np.mod(np.dot(key2, B), mod)
    key2 = np.mod(np.dot(key2, B), mod)

    pub_key = []

    pub_key.append(mod)
    pub_key.append(key1)
    pub_key.append(key2)

    return pub_key, priv_key


def encrypt_matrices(mat, pub_key):

    # encrypt_matrix takes a set of plaintext matrices and a public key,
    # and returns a set of ciphertext matrices

    # Inputs:
    # mat - the list of 2x2 matrix based plaintext to encrypt
    # pub_key - the public key

    # Output:
    # a list of lists of two matrices are returned, representing the
    # ciphertext of each inputted plaintext matrix

    fin_arr = []

    for i in range(len(mat)):
        u = r.randint(1, pub_key[0] - 1)

        while type(mod_num_inverse(u, pub_key[0])) == str:
            u = r.randint(1, pub_key[0] - 1)

        u_inv = mod_num_inverse(u, pub_key[0])

        item0 = r.randint(0, pub_key[0] - 1)
        item1 = r.randint(0, pub_key[0] - 1)

        X_m = np.array([[item0, item1], [item1, item0]])

        while type(mod_matrix_inverse(X_m, pub_key[0])) == str:
            item0 = r.randint(0, pub_key[0])
            item1 = r.randint(0, pub_key[0])
            X_m = np.array([[item0, item1], [item1, item0]])

        X_m_inv = mod_matrix_inverse(X_m, pub_key[0])

        C1 = np.mod(np.dot(u_inv * X_m_inv, pub_key[2]), pub_key[0])
        C1 = np.mod(np.dot(C1, X_m), pub_key[0])

        C2 = np.mod(np.dot(u * mat[i], X_m_inv), pub_key[0])
        C2 = np.mod(np.dot(C2, pub_key[1]), pub_key[0])
        C2 = np.mod(np.dot(C2, X_m), pub_key[0])

        arr = []
        arr.append(C1)
        arr.append(C2)

        fin_arr.append(arr)

    return fin_arr


def decrypt_matrices(ciphertext, priv_key, mod):

    # decrypt_matrices takes a list of a list of two ciphertext matrices, a private key, and a modular base,
    # and returns the set of the original plaintext matrices

    # Inputs:
    # ciphertext - the list of 2 matrix based ciphertext to decrypt
    # priv_key - The private key
    # mod - the modular base

    # Output:
    # decrypt_matrix returns a list of the original plaintext matrices

    fin_arr = []

    for i in range(len(ciphertext)):
        A_inv = mod_matrix_inverse(priv_key[0], mod)
        B_inv = mod_matrix_inverse(priv_key[1], mod)

        d = np.mod(np.dot(A_inv, priv_key[1]), mod)
        d = np.mod(np.dot(d, ciphertext[i][0]), mod)
        d = np.mod(np.dot(d, B_inv), mod)
        d = np.mod(np.dot(d, priv_key[0]), mod)

        d = np.mod(np.dot(ciphertext[i][1], d), mod)

        fin_arr.append(d)

    return fin_arr


def letters_to_nums(letters):

    # This function takes a string, and converts it into a set of 2x2 matrices.
    # The empty space at the end is filled by spaces. Each character is indexed by
    # its ascii decimal value, minus 32 (since indeces 0 to 31 are all whitespace, and
    # therefore hard to show in a string)

    # Inputs:
    # letters - The string to turn into matrices

    # Output:
    # a list of matrices containing the index numbers of each character in the original string

    while len(letters) % 4 != 0:
        letters += " "

    fin_array = []

    for i in range(len(letters) // 4):
        start = i * 4

        fin_array.append(np.array([[ord(letters[start]) - 32, ord(letters[start + 1]) - 32],
                                   [ord(letters[start + 2]) - 32, ord(letters[start + 3]) - 32]]))

    return fin_array


def nums_to_letters(arrs):

    # This function takes a set of 2x2 matrices, and converts them into a string

    # Inputs:
    # arrs - an array of matrices to turn into a string

    # Output:
    # a string

    fin_str = ""

    for i in range(len(arrs)):
        for ii in range(len(arrs[i])):
            for iii in range(len(arrs[i][ii])):
                fin_str += chr(arrs[i][ii][iii] + 32)

    return fin_str


def nums_to_letters_enc(arrs):

    # This does the same as nums_to_letters(), but accounts for there being two matrices in each
    # part of the Khan and Shah ciphertext.

    # Inputs:
    # arrs - an array of an array of 2 matrices to turn into one big string

    # Output:
    # a big string

    fin_str = "<"

    for i in range(len(arrs)):
        for ii in range(len(arrs[i])):
            for iii in range(len(arrs[i][ii])):
                for iiii in range(len(arrs[i][ii])):
                    fin_str += chr(arrs[i][ii][iii][iiii] + 32)

    fin_str += ">"
    return fin_str


def letters_to_nums_enc(str):

    # This does the same as letters_to_nums, but accounts for there being two matrices in each cell
    # of the Khan and Shah ciphertext.

    # Inputs:
    # str - A ciphertext string to turn into an array of an array of integers.

    # Output:
    # an array of an array of character incides.

    fin_arr = []

    for i in range(len(str)//8):
        sub_arr = []
        sub_arr.append(np.array([[ord(str[i*8]) - 32, ord(str[i*8+1]) - 32], [ord(str[i*8+2]) - 32, ord(str[i*8+3]) - 32]]))
        sub_arr.append(np.array([[ord(str[i*8+4]) - 32, ord(str[i*8+5]) - 32], [ord(str[i*8+6]) - 32, ord(str[i*8+7]) - 32]]))

        fin_arr.append(sub_arr)

    return fin_arr

'''
For my senior project, I was tasked with creating a presentation on some mathematical concept,
in this case the K&S cipher. For the end of my presentation, I created the below two functions,
encrypt and decrypt. Neither of these return anything, since the reason of their creation was to
aid a presentation. Instead, they function to show a visual representation of encryption and 
decryption in the console window.

In my presentation, I used these functions as such:
I put my plaintext into the 'encrypt' function below, which converted it to a long, incoherent 
string of jumbled characters. I then copied the printed ciphertext string off the console, for my 
audience to see, and pasted it into the 'decrypt' method, to finish the presentation. This is why 
there is no return statement, and only print statements.
'''

def encrypt(str, pub_key):

    # This takes a string and a public key, converts it to matrices, encrypts the matrices, and then prints a
    # string form of the ciphertext.

    # Inputs:
    # str - The string to encrypt
    # pub_key - The public key

    # Output:
    # the ciphertext string is printed to the console

    print("\nConverting String to Matrix Set...")
    mat = letters_to_nums(str)
    print("\nEncrypting Matrix Set...\n")
    mat = encrypt_matrices(mat, pub_key)

    print(repr(f"Encrypted Code: {nums_to_letters_enc(mat)}"))


def decrypt(str, priv_key, mod):

    # This takes a string, a private key, and a modular base, converts the string to matrices,
    # decrypts the matrices using the key, and then prints a string form of the decrypted ciphertext.

    # Inputs:
    # str - The string to decrypt
    # priv_key - The private key
    # mod - The modular base

    # Output:
    # the plaintext string is printed to the console

    print("\nConverting String to Matrix Set...")
    mat = letters_to_nums_enc(str)
    print("\nDecrypting Matrix Set...\n")
    mat = decrypt_matrices(mat, priv_key, mod)

    print(f"Decrypted Code: {nums_to_letters(mat)}")

