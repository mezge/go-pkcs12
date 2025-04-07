package pkcs12

import "errors"

type Builder struct {
	enc     *Encoder
	entries []any
}

func (enc *Encoder) NewBuilder() *Builder {
	return &Builder{
		enc:     enc,
		entries: make([]any, 0, 10),
	}
}

func (b *Builder) AddTrustStore(tse *TrustStoreEntry) {
	b.entries = append(b.entries, tse)
}

func (b *Builder) AddPrivateKey(kse *KeyStoreEntry) {
	b.entries = append(b.entries, kse)
}

func (b *Builder) Build(password string) ([]byte, error) {
	if b.enc.macAlgorithm == nil && b.enc.certAlgorithm == nil && b.enc.keyAlgorithm == nil && password != "" {
		return nil, errors.New("pkcs12: password must be empty")
	}

	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, err
	}

	var authenticatedSafe []contentInfo
	for _, entry := range b.entries {
		if tse, ok := entry.(*TrustStoreEntry); ok {
			authSafe, err := b.enc.makeTrustBags([]TrustStoreEntry{*tse}, encodedPassword)
			if err != nil {
				return nil, err
			}
			authenticatedSafe = append(authenticatedSafe, authSafe...)

		} else if kse, ok := entry.(*KeyStoreEntry); ok {
			as, err := b.enc.makeKeyBags(*kse, encodedPassword)
			if err != nil {
				return nil, err
			}
			authenticatedSafe = append(authenticatedSafe, as...)
		}
	}
	return b.enc.encodeSafeBags(authenticatedSafe[:], encodedPassword)
}
