# 1. Dữ liệu đầu vào (Từ các bước bạn đã cung cấp)
p = 857504083339712752489993810777
q = 1029224947942998075080348647219
e = 65537

c = 77578995801157823671636298847186723593814843845525223303932
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)

print(f"N: {n}")
print(f"Phi(n): {phi}")
print(f"Private Key (d): {d}")
print(f"Bản rõ: {m}")