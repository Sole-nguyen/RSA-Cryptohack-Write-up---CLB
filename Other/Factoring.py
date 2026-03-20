n = 510143758735509025530880200653196460532653147
p = 19704762736204164635843
q = 25889363174021185185929
def solve_rsa_factoring():
    if p * q == n:
        print("Factoring successful!")
        print(f'min: {min(p,q)}')
def cal_rsa_phi():
    phi = (p-1) * (q-1)
    print(f'phi: {phi}')
    return phi
if __name__ == "__main__":
    solve_rsa_factoring()
    cal_rsa_phi()