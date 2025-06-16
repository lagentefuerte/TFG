import pefile
import math
from collections import Counter

def entropy(data):
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counter.values())

pe = pefile.PE("archivo.exe")

print(f"{'Sección':<10} | {'Entropía'}")
print("-" * 25)

for section in pe.sections:
    name = section.Name.decode().strip('\x00')
    data = section.get_data()
    e = entropy(data)
    print(f"{name:<10} | {e:.2f}")
