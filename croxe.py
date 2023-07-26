from sys import stdout
from time import sleep
from typing import Union
from types import NoneType
from base64 import b64encode, b64decode
from argparse import ArgumentParser
from colorama import Fore, Style, Back
from hashlib import md5, sha1, sha224, sha256, sha384, sha512

# Auther: Muhammed Alkohawaldeh
# github: https://github.com/MASTAR-LAST

JPG_END = "FFD9"

def sprint(text, second=0.03):
    for line in text + '\n':
        stdout.write(line)
        stdout.flush()
        sleep(second)

print(f"""{Fore.CYAN}{Style.BRIGHT}
       _________                         
       __  ____/________________  ______ 
       _  /    __  ___/  __ \_  |/_/  _ \\
       / /___  _  /   / /_/ /_>  < /  __/
       \____/  /_/    \____//_/|_| \___/ 
      
{Fore.LIGHTRED_EX} (01000011 01110010 01101111 01111000 01100101)

{Fore.CYAN}        image injection & extraction tool                              
{Fore.RESET}{Style.RESET_ALL}""")


def injector(imagePath, data, is_file=False, is_encrypt=False):
    try:
        if is_encrypt:
            data = encrypt_data(data, is_file)

        if is_file:
            with open(f"{data}", 'rb') as file:

                Data = file.read()
        else:
            Data = bytes(f'{data}', 'utf-8')

        with open(f'{imagePath}', 'ab') as image:

            image.write(bytes(Data))
    except:
        sprint(f"{Fore.RED}Somthing goes wrong while injecting !{Fore.RESET}")
        exit(1)

def deinjector(imagePath, is_decrypt=False, want_hash=False) -> str:
    with open(f"{imagePath}", 'rb') as image:

        content = image.read()
        offset = content.index(bytes.fromhex(JPG_END))
        image.seek(offset + 2)
        full_content = image.read()

        full_content = full_content.decode('utf-8')
        if is_decrypt:
            try:
                full_content = decrypt_data(full_content)
            except:
                sprint(f"{Fore.RED}Can not decrypt this massge !{Fore.RESET}")
                exit(1)

        return full_content

def encrypt_data(data, is_file=False):
    if is_file:
        with open(f"{data}", 'r') as target_file:
            contant: str = target_file.read()
            message_bytes: bytes = contant.encode('ascii')
            base64_bytes: bytes = b64encode(message_bytes)
            base64_message: str = base64_bytes.decode('ascii')
    else:
        message_bytes: bytes = data.encode('ascii')
        base64_bytes: bytes = b64encode(message_bytes)
        base64_message: str = base64_bytes.decode('ascii')

    return base64_message

def decrypt_data(data):

    message_bytes: bytes = data.encode('ascii')
    base64_bytes: bytes = b64decode(message_bytes)
    string_message: str = base64_bytes.decode('ascii')

    return string_message

def getHash(data, hashType):

    data = data.decode('utf-8')

    match hashType:
        case "sha1":
           hash: str = sha1((data).encode()).hexdigest()

        case "md5":
            hash: str = md5((data).encode()).hexdigest()

        case "sha224":
            hash: str = sha224((data).encode()).hexdigest()

        case "sha256":
            hash: str = sha256((data).encode()).hexdigest()

        case "sha384":
            hash: str = sha384((data).encode()).hexdigest()

        case "sha512":
            hash: str = sha512((data).encode()).hexdigest()

    return hash


if __name__ == '__main__':
    parser = ArgumentParser(prog='python3 croxe.py', description='Photo Injection Tool', epilog="Only JPG images is allowed")
    parser.add_argument('target', help='the image that holding the data')
    parser.add_argument('-D', '--data', help='the data that will be inject in the target')
    # parser.add_argument('-h', '--get-hash', help='get the hash for the data (Default = sha1)', default='sha1')
    parser.add_argument('-e', '--encrypt', help='data encrypt before injecting it (Default = false)', default=False, action='store_true')
    parser.add_argument('-d', '--decrypt', help='data decrypt after extracting it (Default = false)', default=False, action='store_true')
    parser.add_argument('-i', '--inject', help='choose to inject data instead of extracting it (Default = false)', default=False, action='store_true')
    parser.add_argument('-f', '--file', help='determine whether you are content inside a specific file (Default = false)', default=False, action='store_true')
    args = parser.parse_args()

    data: str = args.data
    target: str = args.target
    # wantHash: str = args.get_hash
    wantEncrypt: bool = args.encrypt
    wantDecrypt: bool = args.decrypt
    is_injecting: bool = args.inject
    is_file: bool = args.file

    if wantDecrypt and wantEncrypt:
            sprint(f"{Fore.RED}Please specify if you want to encrypt or decrypt the data{Fore.RESET}")
            exit(1)

    if is_injecting:
        if wantDecrypt:
            sprint(f"{Fore.RED}You can not decrypt data that did not inject at all.{Fore.RESET}")
            exit(1)

        if type(data) == NoneType:
            sprint(f"{Fore.RED}You did not specify the data that you want to injecting it.{Fore.RESET}")
            exit(1)

        if wantEncrypt:
            injector(target, data, is_file=is_file, is_encrypt=True)
            sprint(f"{Fore.LIGHTGREEN_EX}{Style.BRIGHT}Done!{Fore.RESET}{Style.RESET_ALL}")
            exit(0)
        else:
            injector(target, data, is_file=is_file)
            sprint(f"{Fore.LIGHTGREEN_EX}{Style.BRIGHT}Done!{Fore.RESET}{Style.RESET_ALL}")
            exit(0)

    elif not is_injecting:
        if type(data) != NoneType:
            sprint(f"{Fore.RED}You can not put data that does not need while extracting.{Fore.RESET}")
            exit(1)

        if wantDecrypt:
            contant: str = deinjector(target, is_decrypt=True)

        else:
            contant: str = deinjector(target)

        sprint(f"{Style.BRIGHT}Contant ({Fore.YELLOW}Not from the main contant{Fore.RESET}):{Style.RESET_ALL}\n")
        print(f"""{contant}""")
        sprint(f"\n{Fore.LIGHTGREEN_EX}{Style.BRIGHT}Done!{Fore.RESET}{Style.RESET_ALL}")
        exit(0)

            


# filename = md5(('proplem'+'sdfwlkfiowprgnvEFJVO;HIbvioenyeyvgryw3weqvuincmcoqim').encode()).hexdigest()