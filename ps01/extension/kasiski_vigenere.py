'''
Authors: Kimberly Yip, Robbie Young
Last modified: June 30th, 2022
For use in Carleton's CS 341 Cryptography course
kasiski_vigenere.py
'''

from substitution_ciphers import*
from math import gcd

def freq(r):
    char_count = 0
    freq_dic = {'a' : 0, 'b' : 0, 'c' : 0, 'd' : 0, 'e' : 0, 
                'f' : 0, 'g' : 0, 'h' : 0, 'i' : 0, 'j' : 0, 
                'k' : 0, 'l' : 0, 'm' : 0, 'n' : 0, 'o' : 0, 
                'p' : 0, 'q' : 0, 'r' : 0, 's' : 0, 't' : 0,
                'u' : 0, 'v' : 0, 'w' : 0, 'x' : 0, 'y' : 0, 'z' : 0}

    for i in range(len(r)):
        if ord(r[i]) >= 97 and ord(r[i]) <= 122:
            freq_dic[r[i]] += 1
            char_count += 1

    for i in range(26):
        freq_dic[chr(97 + i)] = freq_dic[chr(97 + i)]/char_count

    return freq_dic

def test(k, c, r):
    c = freq(c)
    sum = 0
    for i in range(26):
        sum += r[chr(i + 97)] * c[chr((i - k) % 26 + 97)]
    return sum
  
def breakCaesar(c, r):
    highest_quality = 0
    shift = 0
    for i in range(26):
        this_quality = test(i, c, r)
        if (this_quality > highest_quality):
            shift = i
            highest_quality = this_quality
    return shift
  
def breakVigenere(c, r, l): # cipher_text, reference_text, key_length
    list = []
    for k in range(l):
        list.append(c[k::l])

    key = ''
    for item in list:
        key += chr(breakCaesar(item, r) + 97)
    return key

def vigenere_key_length(c):
    freq_dict = count_Ngram_frequency(c, 3) # most common trigrams in c
    ngrams = sorted(freq_dict, key = freq_dict.get, reverse = True)
    most_freq = ngrams[0:round(0.001 * len(c))] # gets the top 0.1% of the most common trigrams

    lengths_dict = {}
    for this_seq in most_freq:
        positions = [i for i in range(len(c)) if c.upper().startswith(this_seq, i)] # calculates indices of the most frequent trigrams

    distances = []
    for i in range(len(positions) - 1):
        distances.append(positions[i + 1] - positions[i]) # calculates the distances between occurences of each trigrams

    for i in range(len(distances) - 1):
        possible_length = gcd(distances[i], distances[i + 1])
        if possible_length in lengths_dict:
            lengths_dict[possible_length] += 1
        else:
            lengths_dict[possible_length] = 1

    most_frequent = sorted(lengths_dict, key = lengths_dict.get, reverse = True) # gets the most frequent distance, being the expected key length
    return most_frequent[0]
    
def main():
    with open('shakespeare.txt', 'r') as f:
        reference_text = freq(f.read().lower())

    with open('vigenere.txt', 'r') as f:
        cipher_text = "".join(line for line in f)

    length = vigenere_key_length(cipher_text)
    key = breakVigenere(cipher_text, reference_text, length)

    with open('decipher.txt', 'w') as f:
        f.write(vigenere(key)(cipher_text))

if __name__ == '__main__':
    main()