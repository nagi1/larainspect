package schema_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/nagi1/larainspect/internal/report/schema"
)

func TestDraftIsValidJSON(t *testing.T) {
	t.Parallel()

	draft := schema.Draft()
	if len(draft) == 0 {
		t.Fatal("expected non-empty schema draft")
	}

	var decoded map[string]any
	if err := json.Unmarshal(draft, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
}

func TestDraftVersionMatchesEmbeddedSchema(t *testing.T) {
	t.Parallel()

	draft := schema.Draft()
	if !bytes.Contains(draft, []byte(`"const": "`+schema.DraftVersion()+`"`)) {
		t.Fatalf("embedded draft does not include schema version %q", schema.DraftVersion())
	}
}
