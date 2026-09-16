package backup_test

import (
	"path/filepath"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoveryclient/guardtest"
)

// Nothing in this server opens a capsule sealed to the suite key, combines shares or rebuilds
// the key from a seed, except the restore subcommand. The drill opens only a capsule sealed
// to a key the lib generated and dropped inside the call.
func TestNothingInTheServerDecrypts(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	guardtest.NoDecryptOutside(t, root, map[string][]string{
		filepath.Join("cmd", "kyidentity", "main.go"): {"restore"},
	})
}
