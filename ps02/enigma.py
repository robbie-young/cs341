"""
enigma.py
Authors: Robbie Young, Antonio Marino
Initially implemented by David Liben-Nowell
"""

import time

import argparse
from email import message
from heapq import merge
from mimetypes import init
from operator import mod
from re import A
import this
from tracemalloc import start
from substitution_ciphers import ltr2int, int2ltr, ALPHABET

# Details on the rotors as listed here are from a variety of online
# sources.  Rotor details come from Tony Sale's Codes and Ciphers.
# The "double stepping" action is explained by David Hamer and by the
# Crypography Musuem site.  Wikipedia is also (somewhat) helpful for
# some portions of this.  For more:
#
#   https://www.codesandciphers.org.uk/enigma/
#   http://web.archive.org/web/*/www.intelligenia.org/downloads/rotors1.pdf
#   https://en.wikipedia.org/wiki/Enigma_rotor_details
#   https://www.cryptomuseum.com/crypto/enigma/working.htm

ROTOR_PERMUTATIONS = {
    "I"   :       "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
    "II"  :       "AJDKSIRUXBLHWTMCQGZNPYFVOE",
    "III" :       "BDFHJLCPRTXVZNYEIWGAKMUSQO",
    "IV"  :       "ESOVPZJAYQUIRHXLNFTGKDCMWB",
    "V"   :       "VZBRGITYUPSDNHLXAWMJQOFECK",
    "reflector" : "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "plugboard" : "ABCDEFGHIJKLMNOPQRSTUVWXYZ" # Question 1
}

ROTOR_TURNOVERS = {
    "I"   :       "R",  # rotor I's causes its neighbor wheel to step on 
    "II"  :       "F",  #    transition from Q -> R.  Similarly, II steps
    "III" :       "W",  #    its neighbor on E -> F, III on V -> W, etc.
    "IV"  :       "K",  # Royal Flags Wave Kings Above!   
    "V"   :       "A",  # 
    "reflector" :  "",   # (reflectors never rotate)
    "plugboard" : "" # Question 1
}

# Question 1
PLUGBOARD_MAPPING = {
    "A" : "A", "B" : "B", "C" : "C", "D" : "D", "E" : "E",
    "F" : "F", "G" : "G", "H" : "H", "I" : "I", "J" : "J",
    "K" : "K", "L" : "L", "M" : "M", "N" : "N", "O" : "O",
    "P" : "P", "Q" : "Q", "R" : "R", "S" : "S", "T" : "T",
    "U" : "U", "V" : "V", "W" : "W", "X" : "X", "Y" : "Y", "Z" : "Z"
}

# Question 1
"""
Takes in a dictionary of already existing plugboard 
mappings, and a list of lists, where each sublist 
contains two different characters of which the swap 
is to be performed on.
"""
def perform_swaps_on_two_chars(PLUGBOARD_MAPPING, swaps):
    for swap in swaps:
        PLUGBOARD_MAPPING[swap[0]] = swap[1]
        PLUGBOARD_MAPPING[swap[1]] = swap[0]
    return PLUGBOARD_MAPPING

# Question 1
"""
Takes in a string representing the mapping of letters 
in the alphabet if the plugboard was a rotor, as well 
as a dictionary of already exisitng plugboard mappings
"""
def modify_letter_perm(initial_perm, PLUGBOARD_MAPPING):
    modified_list = []
    for character in initial_perm:
        modified_list.append(PLUGBOARD_MAPPING[character])
    return modified_list

# Question 1
"""
Takes in a dictionary of already exisitng plugboard 
mappings, a string representing the mapping of letters 
in the alphabet if the plugboard was a rotor, and a 
list of lists, where each sublist contains two 
different characters of which the swaps are to be 
performed on.
"""
def plugboard_swaps(PLUGBOARD_MAPPING, initial_perm, swaps):
    PLUGBOARD_MAPPING = perform_swaps_on_two_chars(PLUGBOARD_MAPPING, swaps)
    modified_list = modify_letter_perm(initial_perm, PLUGBOARD_MAPPING)
    return modified_list

class Rotor:
    def __init__(self, name, ring_setting, initial_window_setting):
        self.perm = ROTOR_PERMUTATIONS[name]
        if name == "plugboard": # Question 1
            self.perm = list(ROTOR_PERMUTATIONS[name])
            self.perm = plugboard_swaps(PLUGBOARD_MAPPING, self.perm, ring_setting)
            self.perm = "".join(self.perm)
        self.notches = ROTOR_TURNOVERS[name]
        self.position = ltr2int(initial_window_setting)

        # We'll also need the inverse permutation for the letters
        # coming back through this rotor.  E.g., the inverse of
        # ABCDEFGHIJKLMNOPQRSTUVWXYZ    ABCDEFGHIJKLMNOPQRSTUVWXYZ
        # EKMFLGDQVZNTOWYHXUSPAIBRCJ is UWYGADFPVZBECKMTHXSLRINQOJ
        # as (for example) pi[A] = E <==> pi_inverse[E] = A.
        if name != "plugboard": # Question 1
            self.inverse = [None for i in range(26)]
            for i in range(26):
                self.inverse[ltr2int(self.perm[i])] = int2ltr(i)
            self.inverse = "".join(self.inverse)

    def __repr__(self):
        '''Returns the letter showing in the rotor's window.'''
        return int2ltr(self.position)

    def advance(self):
        '''Steps the rotor one position forwards.'''
        self.position = (self.position + 1) % 26

    def in_notch(self):
        '''Reports whether the rotor is sitting in a notch position, 
           aka if we and our left-hand neighbor should step on the 
           next move.'''
        return int2ltr((self.position + 1) % 26) in self.notches

    def encode(self, ch, inverted=False):
        '''Transforms ch by the rotor's permutation (or its inverse).'''
        incoming = (ltr2int(ch) + self.position) % 26
        if not inverted:
            out = (ltr2int(self.perm[incoming]) - self.position) % 26
        else:
            out = (ltr2int(self.inverse[incoming]) - self.position) % 26
        return int2ltr(out)

def enigma(slow, medi, fast,
           plugboard_pairs, ring_setting, initial_position):
    slowR = Rotor(slow, ring_setting[0], initial_position[0])
    mediR = Rotor(medi, ring_setting[1], initial_position[1])
    fastR = Rotor(fast, ring_setting[2], initial_position[2])
    reflector  = Rotor("reflector", "A", "A")
    plugboard = Rotor("plugboard", plugboard_pairs, "A") # Question 1
                
    def encipher(message, debug=False):
        output = ""
        windows, transformations = ["%s%s%s" % (slowR,mediR,fastR)], ""
        for ch in message:
            transformations = transformations + ch
            mfLeverActive = fastR.in_notch()
            smLeverActive = mediR.in_notch()
            if smLeverActive: slowR.advance()
            if smLeverActive or mfLeverActive: mediR.advance()
            fastR.advance()

            ch = plugboard.encode(ch) # Question 1
            transformations = transformations + " => " + ch

            windows.append("%s%s%s" % (slowR,mediR,fastR))
            for rotor in [fastR, mediR, slowR, reflector]:
                ch = rotor.encode(ch)
                transformations = transformations + " -> " + ch
            for rotor in [slowR, mediR, fastR]:
                ch = rotor.encode(ch, inverted=True)
                transformations = transformations + " -> " + ch
            ch = plugboard.encode(ch) # Question 1
            output += ch
            transformations = transformations + "\n"
        if debug:
            return output, " ".join(windows), transformations
        return output
    return encipher

# Question 2
"""
Takes in an already ordered list, and two 
unordered lists of numbers, merging one 
item from the unordered lists into the ordered list.
"""
def merge_an_item(ordered_list, list1, list2):
    if len(list1) == 0:
        ordered_list, list2 = ordered_list+list2,[]
    elif len(list2) == 0:
        ordered_list,list1 = ordered_list+list1, []
    else:
        if list1[0] >= list2[0]:
            ordered_list.append(list1[0])
            list1.pop(0)
        elif list2[0] > list1[0]:
            ordered_list.append(list2[0])
            list2.pop(0)
    return ordered_list, list1, list2

# Question 2
"""
Takes in two seperately ordered lists, 
and joins them together into one ordered list
"""
def join_and_order_lists(list1, list2):
    ordered_list = []
    while len(list1 + list2) != 0:
        ordered_list, list1, list2 = merge_an_item(ordered_list, list1, list2)
    return ordered_list
    
# Question 2
"""
Takes in a list and sorts it
"""
def merge_sort(list_of_values):
    if len(list_of_values) == 1:
        return list_of_values
    else:
        first_half, second_half = merge_sort(list_of_values[0:len(list_of_values)//2]), merge_sort(list_of_values[len(list_of_values)//2:])
        return join_and_order_lists(first_half, second_half)

# Question 2
"""
adds a edge to a list of lists called list_of_cycles 
where each sublist represents an edge that will 
be used to form cycles, a dictionary of letters 
representing edges already added to list_of_cycles,
and the alphabetical chars that will compose that edge
"""
def add_to_list_of_cycles(list_of_cycles, found_letters, this_char, next_char):
    this_cycle = []
    this_cycle.append(this_char)
    this_cycle.append(next_char)
    list_of_cycles.append(this_cycle)
    found_letters[this_char] = 1
    return list_of_cycles, found_letters

# Question 2
"""
Initializes a lists of chains used to create cycles 
and a dictionary that will aid in finding more chains
"""
def initialize_list_of_cycles_and_found_letters():
    list_of_cycles, found_letters = [], {
        "A" : 0, "B" : 0, "C" : 0, "D" : 0, "E" : 0,
        "F" : 0, "G" : 0, "H" : 0, "I" : 0, "J" : 0,
        "K" : 0, "L" : 0, "M" : 0, "N" : 0, "O" : 0,
        "P" : 0, "Q" : 0, "R" : 0, "S" : 0, "T" : 0,
        "U" : 0, "V" : 0, "W" : 0, "X" : 0, "Y" : 0, "Z" : 0}
    return list_of_cycles, found_letters

# Question 2
"""
takes in Enigma settings and generates the 
chains used to create the cycles from which 
the signature will be calculated
"""
def gen_cycle_chains(slow, medi, fast, plugboard_pairs, ring_setting, initial_position):
    list_of_cycles, found_letters = initialize_list_of_cycles_and_found_letters()
    for i in range(26):
        this_char = enigma(slow, medi, fast, plugboard_pairs, ring_setting, initial_position)(int2ltr(i))[-1]
        if found_letters[this_char] == 0:
            next_char = enigma(slow, medi, fast,plugboard_pairs, ring_setting, initial_position)(int2ltr(i) * 4)[-1]
            list_of_cycles, found_letters = add_to_list_of_cycles(list_of_cycles, found_letters, this_char, next_char)
    return list_of_cycles

# Question 2
"""
combines edges in list_of_cycles to a 
particular cycle if there is an edge that 
connects to that cycle in index i of the list of 
edges
"""
def combine_cycle_chains(list_of_cycles, cycle, i):
    if cycle[0] == list_of_cycles[i][-1]:
        cycle.insert(0, list_of_cycles[i][0])
        list_of_cycles[i] = []
    elif cycle[-1] == list_of_cycles[i][0]:
        cycle.append(list_of_cycles[i][-1])
        list_of_cycles[i] = []
    return list_of_cycles, cycle
    
# Question 2
"""
removes empty lists from the inputed list 
of lists
"""
def remove_empty_lists(list_of_cycles):
    while [] in list_of_cycles:
        list_of_cycles.remove([])
    return list_of_cycles

# Question 2
"""
Takes in an empty list that will hold a 
list of list representing cycles called 
cycles_list; a list of lists, where each 
sublist represents an edge in a graph
called list_of_cycles; and a cycle to 
which this function will connect edges
"""
def modify_list_of_cycles(cycles_list, list_of_cycles, cycle):
    for j in range(len(list_of_cycles)):
        i = 0
        while i < len(list_of_cycles):
            list_of_cycles, cycle = combine_cycle_chains(list_of_cycles, cycle, i)
            i +=1
        list_of_cycles = remove_empty_lists(list_of_cycles)
    cycles_list.append(cycle)
    return cycles_list, list_of_cycles    

# Question 2
"""
Takes in a list of lists, where each 
sublist represents an edge in a graph
"""
def combine_chains(list_of_cycles):
    cycles_list = []
    while len(list_of_cycles) != 0:
        cycle = list_of_cycles[0]
        list_of_cycles.pop(0)
        cycles_list, list_of_cycles = modify_list_of_cycles(cycles_list, list_of_cycles, cycle)
    for cycle_index in range(len(cycles_list)):
        cycles_list[cycle_index].pop(0)
    return cycles_list

# Question 2
"""
Takes in a list of lists, and returns 
the lengths of each of these sublists 
in a new list
"""
def convert_to_lengths(cycles_list):
    lengths_list = []
    for item in cycles_list:
        lengths_list.append(len(item))
    return lengths_list

# Question 2
"""
Takes in Enigma settings, and computes the signature
"""
def compute_signature(slow, medi, fast, plugboard_pairs, ring_setting, initial_position):
    list_of_cycles = gen_cycle_chains(slow, medi, fast, plugboard_pairs, ring_setting, initial_position)
    cycles_list = combine_chains(list_of_cycles)
    lengths_list = convert_to_lengths(cycles_list)
    return tuple(merge_sort(lengths_list))

# Question 4
"""
generates a list of lists representing possible 
rotor permutations
"""
def gen_rotor_perms():
    rotor_permutations, rotors = [], ['I','II','III','IV','V']
    for rotor_1 in rotors: 
        for rotor_2 in rotors:
            for rotor_3 in rotors:
                if (rotor_1 != rotor_2) and (rotor_1 != rotor_3) and (rotor_2 != rotor_3):
                    rotor_permutations.append([rotor_1, rotor_2, rotor_3])
    return rotor_permutations

# Question 4
"""
generates a list of strings representing possible 
starting positions
"""
def gen_starting_positions():
    starting_positions = []
    for char_1 in ROTOR_PERMUTATIONS["plugboard"]:
        for char_2 in ROTOR_PERMUTATIONS["plugboard"]:
            for char_3 in ROTOR_PERMUTATIONS["plugboard"]:
                starting_positions.append(char_1 + char_2 + char_3)
    return starting_positions

# Question 4
"""
generates two lists representing rotor permutations 
and starting positions of the Enigma machine
"""
def gen_configs():
    # generate all possible permutations of three out of five rotors
    # generate all possible starting positions
    rotor_permutations, starting_positions = gen_rotor_perms(), gen_starting_positions()
    return rotor_permutations, starting_positions

# Question 4
"""
takes in a dictionary of signatures to configurations, 
and adds signature, configuration key-value pair
"""
def add_config_to_sig(sig_to_config_dict, signature, config):
    if signature in sig_to_config_dict:
        sig_to_config_dict[signature].append(config)
    else:
        sig_to_config_dict[signature] = [config]
    return sig_to_config_dict

# Question 4
"""
Takes in a dictionary of signatures to configurations,
a list representing a particular rotor permutation, and 
a string representing a particular starting position; and 
adds the corresponding signature, configuration key-value pair
"""
def create_sig_to_config_dict(sig_to_config_dict, rotor_perm, starting_pos):
    signature = compute_signature(rotor_perm[0], rotor_perm[1], rotor_perm[2], [], "AAA", starting_pos)
    config = [rotor_perm[0], rotor_perm[1], rotor_perm[2], [], "AAA", starting_pos] 
    sig_to_config_dict = add_config_to_sig(sig_to_config_dict, signature, config)
    return sig_to_config_dict

# Question 4
"""
computes the signature for a list of lists representing all 
rotor permutations and a list of strings representing all 
starting positions 
"""
def compute_sigs_for_configs(rotor_permutations, starting_positions):
    sig_to_config_dict = {}
    for rotor_perm in rotor_permutations:
        for starting_pos in starting_positions:            
            # write to dictionary(keys being the signature, values being the configuration)
            sig_to_config_dict = create_sig_to_config_dict(sig_to_config_dict, rotor_perm, starting_pos)
    return sig_to_config_dict

# Question 4
"""
writes a dictionary to the file sig_to_config.txt
"""
def write_to_sig_to_config_file(sig_to_config_dict):
    with open("sig_to_config.txt", "w") as f:
        for key in sig_to_config_dict:
            f.write(str(key) + ":" + str(sig_to_config_dict[key]) + "\n")
    return 

# Question 4
"""
generates a signature to configuration dictionary of all 
possible configurations and writes that dictionary to a file
"""
def sig_to_config_dictionary():
    # generate every possible configuration
    rotor_permutations, starting_positions = gen_configs()
    # compute the signature for every possible configuration
    sig_to_config_dict = compute_sigs_for_configs(rotor_permutations, starting_positions)
    # write to file
    write_to_sig_to_config_file(sig_to_config_dict)
    return

def main():
    sig_to_config_dictionary()

if __name__ == "__main__":
    main()