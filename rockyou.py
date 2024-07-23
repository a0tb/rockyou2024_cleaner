import re
from multiprocessing import Pool, cpu_count
import os
# twitter/X : @aotb
input_file = "rockyou2024.txt"
output_file = "rockyou_cleaned.txt"
chunk_size = 10**6  # chunk size based on your memory capacity

patterns = [
    re.compile('^[0-9a-f]{32}$'),  # MD5
    re.compile('^[0-9a-f]{40}$'),  # SHA-1
    re.compile('^[0-9a-f]{64}$'),  # SHA-256
    re.compile('^[0-9a-f]{128}$'),  # SHA-512
    re.compile('^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$'),  # Standard bcrypt
    re.compile('^\$2[aby]\$[0-9]{2}\$[A-Za-z0-9./]{53,}$'),  # Extended bcrypt
    re.compile('^[A-Za-z0-9]{40}$'),  # Alphanumeric password of 40 characters
    re.compile('^[5\$][A-Za-z0-9]{53}$'),  # Pattern starting with 5$ followed by 53 alphanumeric characters
    re.compile('^\$2a\$05\$[A-Za-z0-9./]{53}$'),  # bcrypt with specific cost factor and 53 characters
    re.compile('^\$2a\$[0-9]{2}\$[A-Za-z0-9./]{22,}$'),  # bcrypt with variable length
    re.compile('^![A-Za-z0-9]{39}$'),  # Pattern starting with ! followed by 39 alphanumeric characters
    re.compile('^[A-Za-z0-9+/]{64}$'),  # Base64 encoded string
    re.compile('^[A-Za-z0-9+/]{32}$'),  # Base64 encoded string of length 32
    re.compile('^[A-Za-z0-9+/]{128}$'),  # Base64 encoded string of length 128
    re.compile('^\$H\$[0-9a-zA-Z./]{31}$'),  # Drupal hash
    re.compile('^[A-Za-z0-9./]{64}$'),  # Generic hash with 64 characters
    re.compile('^\$2a\$08\$[A-Za-z0-9./]{22}\$[A-Za-z0-9./@._-]+$'),  # Generalized bcrypt with various salts
    re.compile('^[A-Za-z0-9./]{40,}$'),  # General alphanumeric with special characters, 40 or more characters
    re.compile('^\$5\$rounds=[0-9]+\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$'),  # SHA-256 crypt
    re.compile('(%[0-9A-Fa-f]{2})+'),  # Percent-encoded strings
    re.compile('^[0-9a-f]{128}$'),  # Hexadecimal strings of 128 characters
    re.compile('^[0-9a-f]{64}\s[&$A-Za-z0-9.\-_*]+$'),  # Hexadecimal with special characters
    re.compile('^\$P\$[A-Za-z0-9./]{31}$'),  # Patterns like $P$BYvy9fyMIYwVNUpspZi2wU3i0E5YAy0
    re.compile('^"[0-9a-f]{32}\s[A-Za-z0-9!"#$%&\'()*+,\-./:;<=>?@[\\]^_`{|}~]+$'),  # Hexadecimal with special characters in quotes
    re.compile('^![A-Za-z0-9]{36,}$'),  # Pattern starting with ! followed by 36+ alphanumeric characters
    re.compile('^\$2a\$08\$[A-Za-z0-9./]{22}\$[A-Za-z0-9./@._-]+$'),  # Generalized bcrypt with various salts and emails
    re.compile('^"[0-9a-f]{32}\s[^\s]+$'),  # Hexadecimal with any non-space characters
    re.compile('^"[0-9a-f]{32}"$'),  # Hexadecimal strings of 32 characters enclosed in quotes
    re.compile('^\$2a\$05\$[A-Za-z0-9./]{16,53}$'),  # Generalized bcrypt hashes with various lengths
    # re.compile('REGEX') # your own regex 
]

def filter_lines(lines):
    filtered = [
        line for line in lines 
        if line.strip() and not any(pattern.match(line.strip()) for pattern in patterns)
    ]
    return filtered

def process_chunk(chunk_start):
    with open(input_file, 'r', encoding='utf-8') as f:
        f.seek(chunk_start)
        lines = f.readlines(chunk_size)
        return filter_lines(lines)

if __name__ == "__main__":
    file_size = os.path.getsize(input_file)
    chunk_starts = range(0, file_size, chunk_size)
    
    with Pool(cpu_count()) as pool:
        with open(output_file, 'w', encoding='utf-8') as outfile:
            for filtered_chunk in pool.imap(process_chunk, chunk_starts):
                outfile.writelines(filtered_chunk)
    
    print("complete")
