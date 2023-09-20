//go:build piv

/*
Copyright 2022 Gravitational, Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package keys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"testing"

	"github.com/go-piv/piv-go/piv"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/lib/utils/prompt"
)

// TestGetOrGenerateYubiKeyPrivateKey tests GetOrGenerateYubiKeyPrivateKey.
func TestGetOrGenerateYubiKeyPrivateKey(t *testing.T) {
	// This test expects a yubiKey to be connected with default PIV
	// settings and will overwrite any PIV data on the yubiKey.
	if os.Getenv("TELEPORT_TEST_YUBIKEY_PIV") == "" {
		t.Skipf("Skipping TestGenerateYubiKeyPrivateKey because TELEPORT_TEST_YUBIKEY_PIV is not set")
	}

	ctx := context.Background()
	resetYubikey(ctx, t)

	// Generate a new YubiKeyPrivateKey.
	priv, err := GetOrGenerateYubiKeyPrivateKey(false)
	require.NoError(t, err)

	// Test creating a self signed certificate with the key.
	digest := []byte{100}
	_, err = priv.Sign(rand.Reader, digest, nil)
	require.NoError(t, err)

	// Another call to GetOrGenerateYubiKeyPrivateKey should retrieve the previously generated key.
	retrievePriv, err := GetOrGenerateYubiKeyPrivateKey(false)
	require.NoError(t, err)
	require.Equal(t, priv, retrievePriv)

	// parsing the key's private key PEM should produce the same key as well.
	retrieveKey, err := ParsePrivateKey(priv.PrivateKeyPEM())
	require.NoError(t, err)
	require.Equal(t, priv, retrieveKey)
}

func TestOverwriteSlot(t *testing.T) {
	// This test expects a yubiKey to be connected with default PIV
	// settings and will overwrite any PIV data on the yubiKey.
	if os.Getenv("TELEPORT_TEST_YUBIKEY_PIV") == "" {
		t.Skipf("Skipping TestGenerateYubiKeyPrivateKey because TELEPORT_TEST_YUBIKEY_PIV is not set")
	}

	ctx := context.Background()
	resetYubikey(ctx, t)

	oldStdin := prompt.Stdin()
	t.Cleanup(func() { prompt.SetStdin(oldStdin) })

	// Set a non-teleport certificate in the slot.
	y, err := findYubiKey(0)
	require.NoError(t, err)
	yk, err := y.open()
	require.NoError(t, err)

	priv, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err)
	cert, err := metadataCertificateTemplate()
	require.NoError(t, err)
	cert.Subject.Organization = []string{"not-teleport"}
	cert.PublicKey = priv.Public()
	cert.Raw, err = x509.CreateCertificate(rand.Reader, cert, cert, priv.Public(), priv)
	require.NoError(t, err)

	require.NoError(t, yk.SetCertificate(piv.DefaultManagementKey, pivSlotNoTouch, cert))
	require.NoError(t, yk.Close())

	// Fail to overwrite slot when user denies
	prompt.SetStdin(prompt.NewFakeReader().AddString("n"))
	_, err = GetOrGenerateYubiKeyPrivateKey(false)
	require.Error(t, err)

	// Successfully overwrite slot when user accepts
	prompt.SetStdin(prompt.NewFakeReader().AddString("y"))
	_, err = GetOrGenerateYubiKeyPrivateKey(false)
	require.NoError(t, err)
}

// resetYubikey connects to the first yubiKey and resets it to defaults.
func resetYubikey(ctx context.Context, t *testing.T) {
	t.Helper()
	y, err := findYubiKey(0)
	require.NoError(t, err)
	yk, err := y.open()
	require.NoError(t, err)
	require.NoError(t, yk.Reset())
	require.NoError(t, yk.Close())
}
