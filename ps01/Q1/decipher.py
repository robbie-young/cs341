'''
Authors: Kimberly Yip, Robbie Young
Last modified: June 30th, 2022
For use in Carleton's CS 341 Cryptography course
decipher.py
'''

from substitution_ciphers import*

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
  
def breakVigenere(c, r):
    highest_length = 0
    length_dict = {}
    highest_quality = 0
    for i in range(1,100):
        length_dict[c[0::i]] = i
    for key in length_dict:
        for j in range(26):
            this_quality = test(j, key, r)
            if (this_quality > highest_quality * 1.05):
                highest_quality = this_quality
                highest_length = length_dict[key]

    list = []
    for k in range(highest_length):
        list.append(c[k::highest_length])

    key = ''
    for item in list:
        key += chr(breakCaesar(item, r) + 97)
    return key
  
def main():
    with open('shakespeare.txt', 'r') as r:
        reference_text = freq(r.read().lower())

    with open('caesar.txt', 'r') as c:
        ciphertext = c.read().lower()

    with open('vigenere.txt', 'r') as v:
        ciphertextv = v.read().lower()
    
    with open('caeser_decipher.txt', 'w') as cd:
        cd.write(caesar(breakCaesar(ciphertext, reference_text))(ciphertext))
    
    with open('vigenere_decipher.txt', 'w') as vd:
        vd.write(vigenere(breakVigenere(ciphertextv, reference_text))(ciphertextv))

if __name__ == '__main__':
    main()