import os
import random
import string

def normal():
    domains = ["google.com", "ensia.edu.dz", "facebook.com", "wikipedia.org"]
    return random.choice(domains)

def malicious():
    sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=25))
    return f"{sub}.evil.com"

for _ in range(50):
    domain = normal() if random.random() < 0.5 else malicious()
    os.system(f"dig {domain} > /dev/null")
