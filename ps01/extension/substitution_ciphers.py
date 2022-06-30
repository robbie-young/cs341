# substitution_ciphers.py
# Caesar, Substitution, Vigenere, and Homophonic Substitition ciphers
#
# CS 341 Cryptography, Carleton College
# David Liben-Nowell (dln@carleton.edu)

from collections import defaultdict
import random


# ----- UTILITY FUNCTIONS ---------------------------------------------------- #

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
alphabet = "abcdefghijklmnopqrstuvwxyz"

def ltr2int(ch):
    '''Translate letters (upper or lower case) to indices {0, 1, ..., 25}'''
    return ord(ch.upper()) - ord('A')

def int2ltr(i):
    '''Translate indices {0, 1, ..., 25, 26=0, 27=1, ...} to (upper case)
       letters, wrapping around as necessary.'''
    return chr(i % 26 + ord('A'))

def load_file(filename):
    '''Load all of the text from the given file into a single string.'''
    with open(filename, "r") as f:
        s = "".join(line for line in f)
    return s

def count_Ngram_frequency(text, n=1):
    '''Count all sequences of N consecutive letters in the given string,
       and return a (default) dictionary of those counts.  Does NOT
       maintain case; all counts are for the input string converted to
       all upper case.  (So n=1 is unigrams, n=2 is bigrams, etc.)'''
    counts = defaultdict(int)
    for i in range(len(text) - n + 1):
        ngram = text[i:i+n].upper()
        if ngram.isalpha():
            counts[ngram.upper()] += 1
    return counts


# ----- SUBSTITUTION CIPHERS-------------------------------------------------- #
#
# Note: all of these functions are "curried", in the sense that they
# take a key as an argument first, and then return a function that
# enciphers plaintext.  So the usage is
#
#     ciphertext = cipher(key)(plaintext)  # note:  NOT cipher(key,plaintext).
#
# This allows the slow-to-compute ciphers [e.g., one that counts frequencies
# in a reference text] to be reused on multiple plaintexts without recompution.
#
# Also note that all non-alphabetical characters, including spaces, remain
# intact in these implementations.  This would be easy to fix but introduces
# the problem of segmentation of any computationally cracked ciphers -- a pain!


def caesar(shift):
    '''Caesar Cipher: each letter in the plaintext is shifted forward in
       the alphabet by the designated number of letters, wrapping
       around as necessary.  E.g., with a shift of 2, we have A -> C,
       B -> D, ..., X -> Z, Y -> A.  This version maintains plaintext's case.'''

    def encipher(plaintext):
        ciphertext = ""
        for ch in plaintext:
            if ch in ALPHABET:
                ciphertext += int2ltr(ltr2int(ch) + shift)
            elif ch in alphabet:
                ciphertext += int2ltr(ltr2int(ch) + shift).lower()
            else:
                ciphertext += ch
        return ciphertext
    return encipher


def substitution_cipher(starter_key):
    '''Substitution Cipher: the key is a permutation of the alphabet; each
       letter in the plaintext is replaced by its corresponding letter
       in the permutation.  For example, the key "HJDAXGFYBMWONTCVLRQUKSZEPI"
       causes A->H, B->J, C->D, etc.  This code can be used in two ways:

        1) random mode.  If called with key=None, then a random permutation 
           of the alphabet is chosen and used.

        2) key mode.  If called with key != None, then the key
           permutation is derived from the letters in the given key in
           order (deleting duplicates), with any letters missing
           filled in alphabetical order.  For example, for the key ADALOVELACE:
           ADALOVELACE -> ADLOVEC -> ADLOVECBFGHIJKMNPQRSTUWXYZ.

       In either case, this encryption maintains plaintext's case.'''

    if starter_key == None:   
        key = "".join(random.sample(list(ALPHABET),26))  # randomization mode.
    else:                     
        key = starter_key + ALPHABET                     # starter key mode. 
        key = "".join(key[i] for i in range(len(key))    
                      if key[i] not in starter_key[:i])  # (removes duplicates.)

    def encipher(plaintext):
        ciphertext = ""
        for ch in plaintext:
            if ch in ALPHABET:
                ciphertext += key[ltr2int(ch)]
            elif ch in alphabet:
                ciphertext += key[ltr2int(ch)].lower()
            else:
                ciphertext += ch
        return ciphertext
    return encipher


def vigenere(key):
    '''Vigenere Cipher: an interleaved sequence of Caesar shifts; the key
       tells us WHICH Caesar shift to apply to each letter of the plaintext.
       Specifically, the (i)th letter of plaintext is shifted by the (i)th 
       letter of the key -- or, really, by the (i % len(key))th letter of the 
       key.  For example, with the key GRACE and the plaintext HOPPERHOPPER:

          H O P P E R H O P P E R
        + G R A C E|G R A C E|G R
        -------------------------
          N F P R I X Y O R T K I     (For example, P + C = 15 + 2 = 17 = R.)

       This encryption maintains plaintext's case.'''
    
    def encipher(plaintext):
        ciphertext = ""
        for i in range(len(plaintext)):
            shift = ltr2int(key[i % len(key)])
            if plaintext[i] in ALPHABET:
                ciphertext += int2ltr(ltr2int(plaintext[i]) + shift)
            elif plaintext[i] in alphabet:
                ciphertext += int2ltr(ltr2int(plaintext[i]) + shift).lower()
            else:
                ciphertext += plaintext[i]
        return ciphertext
    return encipher

def homophonic_substitution(reference_file, alphabet_size):
    '''Homophonic Substitution Cipher: a (randomized) substitution cipher,
       built to ensure nearly equal frequencies of all symbols in the
       ciphertext (for a plaintext distributed as normal English).
       Specifically, given a reference text, we allocate symbols {0,
       1, ..., alphabet_size - 1} to each letter, allowing multiple
       symbols per letter, roughly in proportion to the unigram
       frequencies in the reference text.  (Each letter is allocated
       at least one symbol.)  Then, to encode a plaintext, each letter
       is replaced by one of its corresponding symbols, chosen at
       random.  Symbols are allocated based on the "Method of Equal Proportions"
       [https://www.census.gov/population/apportionment/about/computing.html].

       Note: this encryption does NOT maintain case, and everything
       nonalphabetical is stripped out, except newlines.'''

    # Count frequencies in the reference text, and create randomly
    # ordered set of symbols {0, 1, ..., alphabet_size - 1}.
    freq = count_Ngram_frequency(load_file(reference_file))
    unused_symbols = random.sample(range(alphabet_size), alphabet_size)
    # print(unused_symbols)
    symbols = {}

    # Every letter is automatically given one symbol ...
    for ch in ALPHABET:
        symbols[ch] = [unused_symbols.pop()]

    # ... and then each remaining symbol is allocated to the letter i with the
    # largest "need", where need is defined as f[i] / sqrt(n[i] * (n[i] + 1))
    # where f[i] = frequency and n[i] = current number of symbols for letter i.
    need = lambda ch: freq[ch]/(len(symbols[ch]) * (1 + len(symbols[ch])))**0.5
    while len(unused_symbols) > 0:
        neediest = max(ALPHABET, key=need)
        symbols[neediest].append(unused_symbols.pop())

    def encipher(plaintext):
        ciphertext = []
        for ch in plaintext.upper():
            if ch in ALPHABET:
                ciphertext.append(str(random.choice(symbols[ch])))
            elif ch == "\n":
                ciphertext.append(ch)
        return ciphertext
    return encipher



def main():
    print("Here are a few sample encipherments.")
    print()
    print(caesar(random.randint(0,25))("Welcome to Cambridge."))
    print(caesar(random.randint(0,25))("Fancy a punt?"))
    print()
    print(substitution_cipher("ADALOVELACE")("Flee at once.  We are discovered!"))
    print(substitution_cipher(None)("Flee at once.  We are discovered!"))
    print()
    print(vigenere("TURING")("CAMBRIDGEENGLAND"))
    print(vigenere("LEMON")("ATTACKATDAWN"))
    print()
    encipherer = homophonic_substitution("shakespeare.txt",100)
    print(encipherer("GRACEHOPPER"))
    for ch in ALPHABET:
        print("   ", ch, [x for x in range(100) if str(x) in encipherer(ch * 1000)])

if __name__ == "__main__":
    main()
