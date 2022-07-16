#!/usr/bin/env python3

from __future__ import print_function
from collections import Counter
import re

TOP_K = 20
N_GRAM = 1

monogram_freq = [
    "e", "t", "a", "o", "i", "n", "s", "r", "h", "d", "l", "u", "c", "m", "f",
    "y", "w", "g", "p", "b", "v", "k", "x", "q", "j", "z"
]


# Generate all the n-grams for value n
def ngrams(n, text):
    for i in range(len(text) - n + 1):
        # Ignore n-grams containing white space
        if not re.search(r'\s', text[i:i + n]):
            yield text[i:i + n]


# Read the data from the ciphertext
with open('ciphertext.txt') as f:
    text = f.read()

# Count, sort, and print out the n-grams
for N in range(N_GRAM):
    print("-------------------------------------")
    print("{}-gram (top {}):".format(N + 1, TOP_K))
    counts = Counter(ngrams(N + 1, text))  # Count
    sorted_counts = counts.most_common(TOP_K)  # Sort

    for idx in range(len(sorted_counts)):
        ngram, _ = sorted_counts[idx]
        print("{}: {}".format(ngram, monogram_freq[idx]))

    cipher_ = ""
    reverse_ = ""

    for idx in range(len(sorted_counts)):
        ngram, _ = sorted_counts[idx]
        cipher_ += ngram
        reverse_ += monogram_freq[idx]

    print(cipher_)
    print(reverse_)
    print(
        f'tr "{cipher_}" "{reverse_}" < ciphertext.txt > original_lab1_mono.txt'
    )
