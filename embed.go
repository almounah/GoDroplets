package embedder

import _ "embed"

//go:embed bin/key
var Key []byte

//go:embed bin/binary.bin.enc
var PayloadEncrypted []byte
