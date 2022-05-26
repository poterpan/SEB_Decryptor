import gzip
import plistlib
import zlib
import rncryptor


class RNCryptor_modified(rncryptor.RNCryptor):
    def post_decrypt_data(self, data):
        data = data[:-(data[-1])]
        return data


def decrypt_SEB(filename, password):
    cryptor = RNCryptor_modified()

    # Read Original .seb File
    with gzip.open(filename, 'rb') as f:
        file_content = f.read()

    decrypted_data = cryptor.decrypt(file_content[4:], password)
    decompressed_data = zlib.decompress(decrypted_data, 15 + 32)

    with open("result.xml", "wb") as f:
        f.write(decompressed_data)

    with open("result.xml", 'rb') as fp:
        pl = plistlib.load(fp)

    print(pl["startURL"])

    test_url = pl["startURL"]

    with open('result.url', 'w') as f:
        f.write(f"""[InternetShortcut]
URL={test_url}
""")


filepath = input("請輸入檔名(不需副檔名)") + '.seb'
seb_password = input("請輸入密碼")
decrypt_SEB(filepath, seb_password)
