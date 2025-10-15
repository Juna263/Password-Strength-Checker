#!/usr/bin/env python 3
"""
Password Strength Checker
_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_

It checks the strength of a password by:
- Making rule-based checks and predictability
- Checking whether it has appeared in any data leaks (Have I Been Pwned API)
- Suggesting secure passphrases from a wordlist
"""

import hashlib
import math
import requests
import argparse
import sys
import os
import random
import time

#CONFIGURATION
#API location for HaveIBeenPwned passwords.
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"

#adding common passwords and wordlist
DEFAULT_WORDLIST = "wordlist.txt"
COMMON_PASSWORDS_FILE = "common_passwords.txt"

#UTILITIES
def load_set_from_file(path):
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return set(line.strip() for line in f if line.strip())
    #put a txt file into python, strip blanks and whitespaces.
    #return an empty set if the file does not exist.

#load common passowrds into memory so that it can be looked up quickly.
COMMON_PASSWORDS = load_set_from_file(COMMON_PASSWORDS_FILE)

#SCORE
def char_pool_size(pw: str) -> int:
    pool = 0
    if any(c.islower() for c in pw): pool += 26
    if any(c.isupper() for c in pw): pool += 26
    if any(c.isdigit() for c in pw): pool += 10
    if any(not c.isalnum() for c in pw): pool += 32  #rough symbol estimate
    return pool
    #estimate the size of the character pool based on if they are lowercase, uppercase, digits or symbols.

def calculate_entropy(pw: str) -> float:
    pool = char_pool_size(pw)
    if pool == 0:
        return 0.0
    return len(pw) * math.log2(pool)
    #calculate Shannon-style predictability (enthropy) in bits
    #the formula used is : enthropy = length*log2(character_pool_size)
    #the higher the enthropy the stronger the password.

def simple_rules_score(pw: str) -> int:
    score = 0
    if len(pw) >= 8: score += 1
    if len(pw) >= 12: score += 1
    if any(c.islower() for c in pw): score += 1
    if any(c.isupper() for c in pw): score += 1
    if any(c.isdigit() for c in pw): score += 1
    if any(not c.isalnum() for c in pw): score += 1
    if pw.lower() in COMMON_PASSWORDS: score -= 4  # heavy penalty for common passwords
    return score
    #simple rules to give the password a score
    #for instance it will add points for diveristy and length and will penalise if the password is a common one.


def overall_rating(entropy: float, rules_score: int) -> str:
    score = entropy / 10 + rules_score * 2
    if score < 6: return "Weak"
    if score < 12: return "Moderate"
    return "Strong"
    #this combines both entropy and the rule scores and it turns it into a simple overall rating.
    #it will return weak|moderate|strong

#HIBP k-anonymity check
def hibp_check(password: str, pause=1.0) -> int:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]   # send only first 5 chars
    suffix = sha1[5:]   # keep rest local for matching
    #use HIBP API to check if the password has been exposed in past breaches
    #it also implements k-anonymity as only the first 5 characters of SHA1 hash are sent to the API.
    #what it returns is: the count of times the password has been breached, if its not found its 0, if there is an API error its -1.

    # Query HIBP range endpoint
    resp = requests.get(HIBP_RANGE_URL.format(prefix), headers={"User-Agent": "PasswordChecker/1.0"})
    if resp.status_code != 200:
        # API might be down or rate-limiting; -1 signals unknown result
        return -1

    # Iterate through returned hashes and compare suffixes
    for line in resp.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)

    # Pause slightly between requests to be nice to API
    time.sleep(pause)
    return 0

#Passphrase generator
def load_wordlist(path=DEFAULT_WORDLIST):
    if not os.path.exists(path):
        return ["correct", "horse", "battery", "staple", "apple", "mirror", "cloud", "river", "table",
 "sun", "moon", "star", "forest", "mountain", "ocean", "valley", "garden", "forest", "breeze",
 "stone", "brick", "window", "door", "bridge", "island", "meadow", "harbor", "canyon", "prairie",
 "orchard", "meadow", "stream", "cascade", "pebble", "leaf", "root", "branch", "ember", "flame",
 "copper", "silver", "golden", "crystal", "quartz", "paper", "pencil", "canvas", "frame", "needle",
 "thread", "button", "saddle", "compass", "anchor", "beacon", "lantern", "cottage", "castle", "tower",
 "hammer", "anvil", "wheel", "sail", "oar", "maple", "cedar", "pine", "willow", "oak",
 "riverbank", "shore", "dune", "cliff", "glen", "ridge", "summit", "plateau", "trail", "path",
 "clock", "calendar", "journal", "letter", "package", "pillow", "blanket", "quilt", "cup", "mug",
 "spoon", "fork", "knife", "lantern", "torch", "glass", "bottle", "vase", "chair", "bench",
 "sofa", "desk", "lamp", "mirror", "window", "curtain", "carpet", "tile", "brick", "stone",
 "rocket", "engine", "pilot", "captain", "crew", "orbit", "planet", "comet", "meteor", "nebula",
 "echo", "whisper", "shout", "laughter", "silence", "music", "melody", "harmony", "rhythm", "drum",
 "violin", "piano", "guitar", "harp", "trumpet", "flute", "viola", "cello", "bow", "note",
 "riverstone", "seashell", "footpath", "sunrise", "sunset", "daybreak", "midnight", "twilight", "dawn", "dusk"]
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        words = [w.strip() for w in f if w.strip()]
    return words

def generate_passphrase(words=4, sep='-'):
    wl = load_wordlist()
    chosen = [random.choice(wl) for _ in range(words)]
    return sep.join(chosen)
    #generate a random passphrase using those words.

# CLI / main || run full analysis entropy,rules,score,hibp.
def analyze(password: str, do_hibp=True):
    ent = calculate_entropy(password)
    rules = simple_rules_score(password)
    rating = overall_rating(ent, rules)
    hibp_count = None
    if do_hibp:
        try:
            hibp_count = hibp_check(password)
        except Exception:
            hibp_count = -1  # Handle network or API issues gracefully
    

    # Return all results as a structured dictionary
    return {
        "password": password,
        "entropy (THTS)": ent,
        "rules_score": rules,
        "rating": rating,
        "hibp_count": hibp_count
    }

def pretty_print(result):
    print(f"Password: {'*' * min(len(result['password']), 8)} (length {len(result['password'])})")
    print(f"Entropy: {result['entropy']:.1f} bits")
    print(f"Rules score: {result['rules_score']}")
    print(f"Overall rating: {result['rating']}")
    if result['hibp_count'] == -1:
        print("Breach check: unavailable")
    elif result['hibp_count'] == 0:
        print("Breach check: Not found in known breaches")
    else:
        print(f"Breach check: Found {result['hibp_count']} times in breaches — change it!")
    #display the analysis to the user for them to read

# the entry point of when this command is started up from the command line interface
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Password Strength Checker")
    parser.add_argument("--check", "-c", help="Password to check")
    parser.add_argument("--generate", "-g", action="store_true", help="Generate a passphrase")
    parser.add_argument("--words", type=int, default=4, help="Number of words in passphrase")
    args = parser.parse_args()

    # If user requests passphrase generation
    if args.generate:
        print("Suggested passphrase:", generate_passphrase(words=args.words))
        sys.exit(0)

    # If user provides a password to check
    if args.check:
        res = analyze(args.check)
        pretty_print(res)
    else:
        # Display usage help if no arguments are passed
        parser.print_help()

    