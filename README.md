# GoDroplets

## What is it 

A python script that wraps a Go Compiling Toolchain used to Generate Droppers (aka Droplets) made in Go.

The Purpose is to integrate this in the EXPLORATION C2 [https://github.com/maxDcb/C2TeamServer](https://github.com/maxDcb/C2TeamServer)

![logo](exploration-go.png) 

## Requirement

It only works on Linux with:

- python3 and pycryptodome (`pip install pycryptodome`)
- Go installed (>1.23.1) [https://go.dev/doc/install](https://go.dev/doc/install)
- For the DLL to compile you will need mingw (`sudo apt install gcc-mingw-w64`)

## Usage

It generate an exe, a svc and a dll given an exe and some argument. It only work for 64 bits now.

```
python3 scripts/GenerateGoDroplets.py --help                                                                                                   
usage: GenerateGoDroplets.py [-h] [--path PATH] [--arg ARG] [--format {exe,svc,dll,all}] [--output OUTPUT] [--clear]

Generate the Go droplets given a binary.

options:
  -h, --help            show this help message and exit
  --path PATH           Path to the binary to be wrapped to create the Go dropper
  --arg ARG             Argument that are needed for the binary
  --format {exe,svc,dll,all}
                        Format of the droplet, can be exe, svc, dll or all of the above
  --output OUTPUT       Output File Prefix
  --clear               Just Clear the bin directory. If specified will not build anything.

Example: python3 scripts/GenerateGoDroplets.py --path="/home/kali/Desktop/BeaconHttp.exe" --arg="192.168.1.191 8080 http" --format="all"
--output="droplet"
```




