ETHER_TYPES = {}
try:
    while True:
        s = input().split()
        s1 = int(s[0], 16)
        s2 = ''
        for i in range(1, len(s)):
            s2 += s[i]
            if i < len(s) - 1:
                s2 += ' '
        ETHER_TYPES[s1] = s2
except EOFError:
    pass
finally:
    print(ETHER_TYPES)
