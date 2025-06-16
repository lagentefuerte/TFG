
def rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    out = bytearray()

    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])

    return bytes(out)


key = b'supersecreta'
with open("payload_base64.txt", "rb") as f:
    data = f.read()

encrypted = rc4(data, key)

with open("payload.enc", "wb") as f:
    f.write(encrypted)
