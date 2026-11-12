package store

import (
	"regexp"
	"strings"

	"github.com/Busnes-app/kyidentity-server/internal/store/pgdialect"
)

var (
	testTriggerRE = regexp.MustCompile(`(?s)^\s*CREATE TRIGGER (\w+) ((?:BEFORE|AFTER) .+? ON \w+)(?: WHEN (.+?))? BEGIN(.*)END\s*$`)
	testDropRE    = regexp.MustCompile(`^\s*DROP TRIGGER (\w+)\s*$`)
	testRaiseRE   = regexp.MustCompile(`SELECT RAISE\(ABORT,\s*('[^']*')\)`)
)

// dialect renders the SQLite trigger DDL that tests use to inject failures as plpgsql
// when the store runs on Postgres; anything else, and every statement on SQLite, is
// returned unchanged. DROP TRIGGER drops the trigger's function, and with it the trigger.
func dialect(s *Store, q string) string {
	if !s.postgres {
		return q
	}
	if m := testDropRE.FindStringSubmatch(q); m != nil {
		return `DROP FUNCTION ` + m[1] + `() CASCADE`
	}
	m := testTriggerRE.FindStringSubmatch(q)
	if m == nil {
		return q
	}
	name, timing, when, body := m[1], m[2], m[3], m[4]
	body = pgdialect.Translate(testRaiseRE.ReplaceAllString(body, `RAISE EXCEPTION $1`))
	ret := `RETURN NULL;`
	if strings.HasPrefix(timing, "BEFORE") {
		ret = `IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;`
	}
	if when != "" {
		when = ` WHEN (` + pgdialect.Translate(when) + `)`
	}
	return `CREATE FUNCTION ` + name + `() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN ` + body + ` ` + ret + ` END $$;
 CREATE TRIGGER ` + name + ` ` + timing + ` FOR EACH ROW` + when + ` EXECUTE FUNCTION ` + name + `()`
}
