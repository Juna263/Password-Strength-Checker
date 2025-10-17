#!/usr/bin/env python3
"""
Password Strength Checker & Secure Password Generator
_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_

It checks the strength of a password by:
- Making rule-based checks and predictability
- Checking whether it has appeared in any data leaks (Have I Been Pwned API)
- Suggesting secure passphrases from a wordlist
- Generating stronger versions of existing passwords while preserving user's elements
"""

import hashlib
import math
import requests
import argparse
import sys
import os
import random
import time
import secrets
import string

# CONFIGURATION
# API location for HaveIBeenPwned passwords.
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"

# Adding common passwords and wordlist
DEFAULT_WORDLIST = "wordlist.txt"
COMMON_PASSWORDS_FILE = "common_passwords.txt"

# Character sets for password generation
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

# UTILITIES
def load_set_from_file(path):
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return set(line.strip() for line in f if line.strip())
    # Put a txt file into python, strip blanks and whitespaces.
    # Return an empty set if the file does not exist.

# Load common passwords into memory so that it can be looked up quickly.
COMMON_PASSWORDS = load_set_from_file(COMMON_PASSWORDS_FILE)

# SCORE
def char_pool_size(pw: str) -> int:
    pool = 0
    if any(c.islower() for c in pw): pool += 26
    if any(c.isupper() for c in pw): pool += 26
    if any(c.isdigit() for c in pw): pool += 10
    if any(not c.isalnum() for c in pw): pool += 32  # Rough symbol estimate
    return pool
    # Estimate the size of the character pool based on if they are lowercase, uppercase, digits or symbols.

def calculate_entropy(pw: str) -> float:
    pool = char_pool_size(pw)
    if pool == 0:
        return 0.0
    return len(pw) * math.log2(pool)
    # Calculate Shannon-style predictability (entropy) in bits
    # The formula used is: entropy = length * log2(character_pool_size)
    # The higher the entropy the stronger the password.

def simple_rules_score(pw: str) -> int:
    score = 0
    if len(pw) >= 8: score += 1
    if len(pw) >= 12: score += 1
    if any(c.islower() for c in pw): score += 1
    if any(c.isupper() for c in pw): score += 1
    if any(c.isdigit() for c in pw): score += 1
    if any(not c.isalnum() for c in pw): score += 1
    if pw.lower() in COMMON_PASSWORDS: score -= 4  # Heavy penalty for common passwords
    return score
    # Simple rules to give the password a score
    # For instance it will add points for diversity and length and will penalize if the password is a common one.

def overall_rating(entropy: float, rules_score: int) -> str:
    score = entropy / 10 + rules_score * 2
    if score < 6: return "Weak"
    if score < 12: return "Moderate"
    return "Strong"
    # This combines both entropy and the rule scores and it turns it into a simple overall rating.
    # It will return weak|moderate|strong

# HIBP k-anonymity check
def hibp_check(password: str, pause=1.0) -> int:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]   # Send only first 5 chars
    suffix = sha1[5:]   # Keep rest local for matching
    # Use HIBP API to check if the password has been exposed in past breaches
    # It also implements k-anonymity as only the first 5 characters of SHA1 hash are sent to the API.
    # What it returns is: the count of times the password has been breached, if it's not found it's 0, if there is an API error it's -1.

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

# SECURE PASSWORD GENERATOR - NEW FUNCTIONALITY
##   takes the original password and based on the score it will suggest a stronger yet familiar password.
##   steop by step it does the following:
##      1. Analyze what character types are already present
##      2. Ensure all character types are included for diversity
##      3. Add secure random characters to reach minimum length
##      4. Shuffle the result to avoid predictable patterns



def strengthen_password(original_password: str, min_length=12) -> str:
    
    # Start with the original password as base
    strengthened = list(original_password)
    
    # Analyze what character types are already in the password
    has_lower = any(c.islower() for c in original_password)
    has_upper = any(c.isupper() for c in original_password)
    has_digit = any(c.isdigit() for c in original_password)
    has_symbol = any(not c.isalnum() for c in original_password)
    
    # Add missing character types using cryptographically secure random generation
    chars_to_add = []
    
    if not has_lower:
        chars_to_add.append(secrets.choice(LOWERCASE))
    if not has_upper:
        chars_to_add.append(secrets.choice(UPPERCASE))
    if not has_digit:
        chars_to_add.append(secrets.choice(DIGITS))
    if not has_symbol:
        chars_to_add.append(secrets.choice(SYMBOLS))
    
    # Calculate how many more characters we need to reach minimum length
    current_length = len(original_password)
    needed_length = max(0, min_length - current_length)
    
    # If we need more characters beyond the missing types, add random secure ones
    if needed_length > len(chars_to_add):
        additional_needed = needed_length - len(chars_to_add)
        
        # Determine which character sets to use based on what's already in the password
        available_sets = []
        if has_lower or not has_lower:  # Always include lowercase if missing or for variety
            available_sets.append(LOWERCASE)
        if has_upper or not has_upper:  # Always include uppercase if missing or for variety
            available_sets.append(UPPERCASE)
        if has_digit or not has_digit:  # Always include digits if missing or for variety
            available_sets.append(DIGITS)
        if has_symbol or not has_symbol:  # Always include symbols if missing or for variety
            available_sets.append(SYMBOLS)
        
        # Add additional random characters from available sets
        for _ in range(additional_needed):
            char_set = secrets.choice(available_sets)
            chars_to_add.append(secrets.choice(char_set))
    
    # Combine original password with new characters
    strengthened.extend(chars_to_add)
    
    # Shuffle everything to avoid predictable patterns (beginning/end additions)
    secrets.SystemRandom().shuffle(strengthened)
    
    return ''.join(strengthened)


#THIS WILL GIVE USERS OPTIONS TO CHOOSE FROM

def generate_multiple_strengthened(original_password: str, count=3) -> list:
    suggestions = []
    for i in range(count):
        # Vary the minimum length slightly for different options
        varied_min_length = max(12, len(original_password) + secrets.randbelow(6))
        suggestion = strengthen_password(original_password, varied_min_length)
        
        # Ensure uniqueness in suggestions
        if suggestion not in suggestions and suggestion != original_password:
            suggestions.append(suggestion)
    
    return suggestions

# Passphrase generator
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
    # Generate a random passphrase using those words.

# CLI / main || run full analysis entropy, rules, score, hibp.
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
    
    # Generate strengthened password suggestions
    strengthened_suggestions = generate_multiple_strengthened(password)

    # Return all results as a structured dictionary
    return {
        "password": password,
        "entropy": ent,
        "rules_score": rules,
        "rating": rating,
        "hibp_count": hibp_count,
        "strengthened_suggestions": strengthened_suggestions
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
    
    # Display strengthened password suggestions if the password is not strong
    if result['rating'] != "Strong" and result['strengthened_suggestions']:
        print("\n--- STRONGER PASSWORD SUGGESTIONS ---")
        print("Based on your password, here are stronger versions that keep your elements:")
        for i, suggestion in enumerate(result['strengthened_suggestions'], 1):
            suggestion_entropy = calculate_entropy(suggestion)
            print(f"{i}. {suggestion} (Entropy: {suggestion_entropy:.1f} bits)")
        print("\nThese suggestions:")
        print("- Keep all the characters and patterns from your original password")
        print("- Add missing character types (uppercase, lowercase, digits, symbols)")
        print("- Increase length to at least 12 characters")
        print("- Shuffle characters to avoid predictable patterns")
    # Display the analysis to the user for them to read

# The entry point of when this command is started up from the command line interface
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Password Strength Checker & Secure Password Generator")
    parser.add_argument("--check", "-c", help="Password to check")
    parser.add_argument("--generate", "-g", action="store_true", help="Generate a passphrase")
    parser.add_argument("--words", type=int, default=4, help="Number of words in passphrase")
    parser.add_argument("--strengthen", "-s", help="Show strengthened versions of this password")
    args = parser.parse_args()

    # If user requests passphrase generation
    if args.generate:
        print("Suggested passphrase:", generate_passphrase(words=args.words))
        sys.exit(0)
    
    # If user wants to see strengthened versions of a specific password
    if args.strengthen:
        print(f"Original password: {args.strengthen}")
        print("Generating stronger versions while keeping your elements...")
        suggestions = generate_multiple_strengthened(args.strengthen)
        for i, suggestion in enumerate(suggestions, 1):
            entropy = calculate_entropy(suggestion)
            print(f"Option {i}: {suggestion} (Entropy: {entropy:.1f} bits)")
        sys.exit(0)

    # If user provides a password to check
    if args.check:
        res = analyze(args.check)
        pretty_print(res)
    else:
        # Display usage help if no arguments are passed
        parser.print_help()