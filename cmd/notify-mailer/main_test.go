package main

import (
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

var (
	log = blog.UseMock()
)

type testCtx struct {
	dbMap   *gorp.DbMap
	ssa     core.StorageAdder
	mc      *mocks.Mailer
	fc      clock.FakeClock
	m       *mailer
	cleanUp func()
}

func newFakeClock(t *testing.T) clock.FakeClock {
	const fakeTimeFormat = "2006-01-02T15:04:05.999999999Z"
	ft, err := time.Parse(fakeTimeFormat, fakeTimeFormat)
	if err != nil {
		t.Fatal(err)
	}
	fc := clock.NewFake()
	fc.Set(ft.UTC())
	return fc
}

func setup(t *testing.T) *testCtx {
	// We use the test_setup user (which has full permissions to everything)
	// because the SA we return is used for inserting data to set up the test.
	dbMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	if err != nil {
		t.Fatalf("Couldn't connect the database: %s", err)
	}
	fc := newFakeClock(t)
	ssa, err := sa.NewSQLStorageAuthority(dbMap, fc, log)
	if err != nil {
		t.Fatalf("unable to create SQLStorageAuthority: %s", err)
	}
	cleanUp := test.ResetSATestDatabase(t)

	mc := &mocks.Mailer{}

	m := &mailer{
		log:           log,
		mailer:        mc,
		emailTemplate: "",
		dbMap:         dbMap,
		clk:           fc,
	}
	return &testCtx{
		dbMap:   dbMap,
		ssa:     ssa,
		mc:      mc,
		fc:      fc,
		m:       m,
		cleanUp: cleanUp,
	}
}
