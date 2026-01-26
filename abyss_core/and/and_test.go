package and_test

import (
	"testing"

	"github.com/kadmila/Abyss-Browser/abyss_core/and"
)

// TODO: fuzzing

type DummyHost struct {
}

func TestANDBasics(t *testing.T) {
	and.NewAND("local")
}
