'''
Authors: Kimberly Yip, Robbie Young
Last modified: June 30th, 2022
For use in Carleton's CS 341 Cryptography course
homophonic.py
'''

from collections import defaultdict

def sort_dict(dict):
    sorted_dict = {}
    for w in sorted(dict, key = dict.get):
      sorted_dict[w] = dict[w]
    return sorted_dict

def cipher_counts(text, n):
    char_list = text.split(' ')
    counts_dict = {}
    for i in range(len(char_list)):
        this_string = ''
        for j in range(n):
            if (i + j < len(char_list)):
                this_string += char_list[i + j] + ' '
        if (this_string.find('\n') == -1): # checks to see if it is the end of a line. IF so, then it does not add to dict; removes any m-gram where m is less than n
            if this_string in counts_dict:
                counts_dict[this_string] += 1
            else:
                counts_dict[this_string] = 1
    
    return sort_dict(counts_dict)

def main():
    with open('cipher.txt', 'r') as f: # change filename when going from one iteration of deciphering to another
        text = "".join(line for line in f)
        
    with open('key.txt', 'r') as f:
        lines = f.readlines()
        for this_line in lines:
            list = this_line.replace(' ', '').replace('\n', '').split(':') # parsing 
            key = ' ' + list[0] + ' '
            values = list[1].replace('[', '').replace(']', '').split(',') # parsing
            for this_value in values:
                this_value = ' ' + this_value + ' '
                for i in range(3): # to get rid of any repeat characters after one another
                    text = text.replace(this_value, key)
   
    with open('decipher.txt', 'w') as f: # writes deciphered text (maybe partially deciphered text) to a textfile
        f.write(text)
    
    with open('cipher.txt', 'r') as f:
        text = "".join(line for line in f)
  
    cipher_counts_dict = cipher_counts(text, n = 3) # gets n-grams from the provided text file (line 43)
    with open('trigram.txt', 'w') as f:
        for this_key in cipher_counts_dict.keys():
            f.write(this_key + ':' + ' ' + str(cipher_counts_dict[this_key]) + '\n')
    
if __name__ == '__main__':
  main()