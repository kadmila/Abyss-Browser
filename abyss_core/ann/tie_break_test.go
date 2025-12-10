package ann_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/kadmila/Abyss-Browser/abyss_core/ann"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
)

func TestTieBreak(t *testing.T) {
	pkey_A, _ := sec.NewRootPrivateKey()
	id_A, _ := sec.NewAbyssRootSecrets(pkey_A)

	pkey_B, _ := sec.NewRootPrivateKey()
	id_B, _ := sec.NewAbyssRootSecrets(pkey_B)

	tb_res_1, err := ann.TieBreak(id_A.ID(), id_B.ID())
	if err != nil {
		t.Fatal(err)
	}
	tb_res_2, err := ann.TieBreak(id_B.ID(), id_A.ID())
	if err != nil {
		t.Fatal(err)
	}
	tb_res_3, err := ann.TieBreak(id_A.ID(), id_A.ID())
	if err != nil {
		t.Fatal(err)
	}

	// fmt.Println(id_A.ID())
	// fmt.Println(id_B.ID())
	// fmt.Println(tb_res_1)
	// fmt.Println(tb_res_2)
	// fmt.Println(tb_res_3)

	if id_A.ID() != tb_res_3 || tb_res_1 != tb_res_2 {
		t.Fatal(errors.New("impossible result"))
	}
	if tb_res_1 == id_A.ID() {
		fmt.Print("1")
	} else if tb_res_1 == id_B.ID() {
		fmt.Print("2")
	} else {
		t.Fatal(errors.New("result neither"))
	}
}

func TestTieBreakN(t *testing.T) {
	for range 100 {
		TestTieBreak(t)
	}
}

func TestTieBreakLoad(t *testing.T) {
	pkey_A, _ := sec.NewRootPrivateKey()
	id_A, _ := sec.NewAbyssRootSecrets(pkey_A)

	pkey_B, _ := sec.NewRootPrivateKey()
	id_B, _ := sec.NewAbyssRootSecrets(pkey_B)

	tb_res, err := ann.TieBreak(id_A.ID(), id_B.ID())
	if err != nil {
		t.Fatal(err)
	}

	t_before := time.Now()
	for range 1000000 {
		tb_res_r, err := ann.TieBreak(id_A.ID(), id_B.ID())
		if err != nil {
			t.Fatal(err)
		}
		if tb_res != tb_res_r {
			t.Fatal(errors.New("inconsistent"))
		}
	}
	fmt.Println(time.Since(t_before).String())
}
