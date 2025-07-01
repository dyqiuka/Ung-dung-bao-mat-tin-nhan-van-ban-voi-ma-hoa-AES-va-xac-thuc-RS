from Crypto.PublicKey import RSA

def generate_keys(name):
    key = RSA.generate(2048)

    private_key = key.export_key()
    with open(f'{name}_private.pem', 'wb') as f:
        f.write(private_key)

    public_key = key.publickey().export_key()
    with open(f'{name}_public.pem', 'wb') as f:
        f.write(public_key)

    print(f'Đã tạo khóa cho {name}')

if __name__ == '__main__':
    generate_keys('server')
    generate_keys('client')

