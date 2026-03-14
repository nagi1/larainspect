package rules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

// benchSourceTree creates a synthetic source tree with PHP files for rules-engine benchmarking.
func benchSourceTree(b *testing.B, dir string, fileCount int) string {
	b.Helper()

	dirs := []string{
		"app/Http/Controllers",
		"app/Models",
		"config",
		"routes",
		"resources/views",
		"database/migrations",
	}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			b.Fatal(err)
		}
	}

	for i := 0; i < fileCount; i++ {
		var subdir, name, content string
		switch i % 5 {
		case 0:
			subdir = "app/Http/Controllers"
			name = fmt.Sprintf("Controller%d.php", i)
			content = fmt.Sprintf("<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\nclass Controller%d extends Controller {\n  public function store(Request $request) {\n    $data = $request->all();\n    Model::create($data);\n  }\n}\n", i)
		case 1:
			subdir = "app/Models"
			name = fmt.Sprintf("Model%d.php", i)
			content = fmt.Sprintf("<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Model%d extends Model {\n  protected $guarded = [];\n}\n", i)
		case 2:
			subdir = "config"
			name = fmt.Sprintf("config%d.php", i)
			content = "<?php\nreturn ['key' => env('APP_KEY'), 'debug' => env('APP_DEBUG')];\n"
		case 3:
			subdir = "routes"
			name = fmt.Sprintf("routes%d.php", i)
			content = "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::get('/test', fn () => 'ok');\n"
		case 4:
			subdir = "database/migrations"
			name = fmt.Sprintf("migration%d.php", i)
			content = "<?php\nuse Illuminate\\Database\\Migrations\\Migration;\nreturn new class extends Migration {\n  public function up() { Schema::create('t', function($t) { $t->id(); }); }\n};\n"
		}
		if err := os.WriteFile(filepath.Join(dir, subdir, name), []byte(content), 0o644); err != nil {
			b.Fatal(err)
		}
	}

	return dir
}

func BenchmarkMatchFile(b *testing.B) {
	engine, issues := New(model.RuleConfig{})
	if len(issues) > 0 {
		b.Skipf("rule compilation issues: %v", issues)
	}

	content := "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\nclass UserController extends Controller {\n  public function store(Request $request) {\n    $data = $request->all();\n    User::create($data);\n    return redirect('/users');\n  }\n}\n"

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		matches := engine.MatchFile("app/Http/Controllers/UserController.php", content)
		_ = matches
	}
}

func BenchmarkScanRootSmall(b *testing.B) {
	dir := b.TempDir()
	benchSourceTree(b, dir, 20)

	engine, _ := New(model.RuleConfig{})
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		matches, issues := engine.ScanRoot(ctx, dir)
		_ = matches
		_ = issues
	}
}

func BenchmarkScanRootMedium(b *testing.B) {
	dir := b.TempDir()
	benchSourceTree(b, dir, 100)

	engine, _ := New(model.RuleConfig{})
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		matches, issues := engine.ScanRoot(ctx, dir)
		_ = matches
		_ = issues
	}
}
