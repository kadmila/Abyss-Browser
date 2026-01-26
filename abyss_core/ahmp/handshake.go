package ahmp

///// AHMP for abyss handshake

type RawHS1 struct {
	EncryptedCertificate []byte
	EncryptedSecret      []byte
}
