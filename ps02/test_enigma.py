# test_enigma.py
# A few test cases for a partial implementation,
#    for CS 341 Cryptography, Carleton College.
# David Liben-Nowell (dln@carleton.edu)

from enigma import enigma

print("One character transformation sequence, I/II/III AAZ on 'G':")
print("      [https://www.codesandciphers.org.uk/enigma/]")
result = enigma("I","II","III", [], "AAA", "AAZ")("G", debug=True)
print("  correct:   G -> C -> D -> F -> S -> S -> E -> P")
print("  computed: ", result[2])

print("Multicharacter transformation sequence, I/II/III HDX on 'ABCDEF':")
print("      [http://enigmaco.de/enigma/enigma.html]")
print("      [https://cryptii.com/pipes/swiss-enigma]")
result = enigma("I","II","III", [], "AAA", "HDX")("ABCDEF", debug=True)
print("  correct:   KQGJAL")
print("  computed: ", result[0], "\n")

print("Encode/decode sequence, II/I/IV DLN:")
message = "ADMIRALGRACEMURRAYHOPPER"
result = enigma("II", "I", "IV", [], "AAA", "DLN")(message)
decrypt = enigma("II", "I", "IV", [], "AAA", "DLN")(result)
print("  correct: %s" % message)
print("  encoded: %s" % result)
print("  decoded: %s" % decrypt, "\n")

print("Double-step sequence of windows, III/II/I ADO on 'ABCDEF':")
print("      [https://en.wikipedia.org/wiki/Enigma_rotor_details]")
result = enigma("III","II","I", [], "AAA", "ADO")("ABCDEF", debug=True)
print("  correct:   ADO ADP ADQ AER BFS BFT BFU")
print("  computed: ", result[1], "\n")

print("Single-step sequence of windows, I/II/III AAU on 'ABC':")
print("      [https://en.wikipedia.org/wiki/Enigma_rotor_details]")
result = enigma("I","II","III", [], "AAA", "AAU")("ABC", debug=True)
print("  correct:   AAU AAV ABW ABX")
print("  computed: ", result[1], "\n")

print("Double-step sequence of windows, I/II/III ADU on 'ABCDE':")
print("      [http://web.archive.org/web/*/www.intelligenia.org/downloads/rotors1.pdf]")
result = enigma("III","II","I", [], "AAA", "ADO")("ABCDEF", debug=True)
print("  correct:   ADO ADP ADQ AER BFS BFT BFU")
print("  computed: ", result[1], "\n")

# Here are a few of the above tests, with the addition of the plugboard.
# Uncomment these to test your plugboard implementation.

print("One character transformation sequence, I/II/III AAZ on 'G' with plugboard:")
result = enigma("I","II","III", [("G", "B"), ("X", "Z")], "AAA", "AAZ")("G", debug=True)
print("  correct:   G => B -> D -> K -> N -> K -> B -> J -> E")
print("  computed: ", result[2])

print("Multicharacter transformation sequence, I/II/III HDX on 'ABCDEF' with plugboard:")
result = enigma("I","II","III", [("A", "B"), ("X", "Z")], "AAA", "HDX")("ABCDEF", debug=True)
print("  correct:   STGJBL")
print("  computed: ", result[0], "\n")

print("Double-step sequence of windows, I/II/III ADU on 'ABCDE' with plugboard:")
print("      [http://web.archive.org/web/*/www.intelligenia.org/downloads/rotors1.pdf]")
result = enigma("III","II","I", [("A","B"),("Y", "Z"),("C","D")], "AAA", "ADO")("ABCDEF", debug=True)
print("  correct:   ADO ADP ADQ AER BFS BFT BFU")
print("  computed: ", result[1], "\n")
