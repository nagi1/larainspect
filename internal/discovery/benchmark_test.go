package discovery

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nagi1/larainspect/internal/model"
)

// benchLaravelApp creates a realistic Laravel application tree in dir with
// PHP source files, config, routes, views, and migrations. The returned path
// is the application root.
func benchLaravelApp(b *testing.B, dir string, name string) string {
	b.Helper()
	root := filepath.Join(dir, name)

	dirs := []string{
		"app/Http/Controllers",
		"app/Http/Middleware",
		"app/Models",
		"app/Providers",
		"bootstrap/cache",
		"config",
		"database/migrations",
		"public",
		"resources/views",
		"routes",
		"storage/framework/views",
		"storage/logs",
		"vendor/composer",
	}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			b.Fatalf("MkdirAll(%q) error = %v", d, err)
		}
	}

	files := map[string]string{
		"artisan":                          "#!/usr/bin/env php\n<?php require __DIR__.'/vendor/autoload.php';\n",
		"bootstrap/app.php":                "<?php use Illuminate\\Foundation\\Application;\nreturn Application::configure()->create();\n",
		"bootstrap/cache/config.php":       "<?php return ['app' => ['debug' => false, 'key' => 'base64:dGVzdA==']];\n",
		"bootstrap/cache/services.php":     "<?php return [];\n",
		"bootstrap/cache/packages.php":     "<?php return [];\n",
		"public/index.php":                 "<?php require __DIR__.'/../vendor/autoload.php';\n$app = require_once __DIR__.'/../bootstrap/app.php';\n",
		".env":                             "APP_NAME=Benchmark\nAPP_ENV=production\nAPP_KEY=base64:dGVzdHRlc3R0ZXN0dGVzdA==\nAPP_DEBUG=false\nDB_PASSWORD=secret\n",
		"config/app.php":                   "<?php return ['name' => env('APP_NAME'), 'debug' => (bool)env('APP_DEBUG', false)];\n",
		"config/auth.php":                  "<?php return ['defaults' => ['guard' => 'web'], 'guards' => ['web' => ['driver' => 'session']]];\n",
		"config/database.php":              "<?php return ['default' => env('DB_CONNECTION', 'mysql')];\n",
		"config/session.php":               "<?php return ['driver' => 'file', 'secure' => env('SESSION_SECURE_COOKIE')];\n",
		"config/cors.php":                  "<?php return ['paths' => ['api/*'], 'allowed_origins' => ['*']];\n",
		"routes/web.php":                   "<?php use Illuminate\\Support\\Facades\\Route;\nRoute::get('/', fn () => view('welcome'));\nRoute::prefix('admin')->middleware('auth')->group(fn () => null);\n",
		"routes/api.php":                   "<?php use Illuminate\\Support\\Facades\\Route;\nRoute::middleware('throttle:60,1')->group(fn () => null);\n",
		"resources/views/welcome.blade.php": "<html><body>{{ $greeting }}</body></html>",
		"storage/framework/views/cached.php": "<?php echo 'cached view';\n",
	}

	// Composers
	files["composer.json"] = `{
  "name": "acme/benchmark-app",
  "require": {
    "php": "^8.2",
    "laravel/framework": "^11.0",
    "livewire/livewire": "^3.0",
    "filament/filament": "^3.2"
  },
  "require-dev": {
    "laravel/telescope": "^5.0"
  }
}`
	files["composer.lock"] = `{
  "packages": [
    {"name": "laravel/framework", "version": "v11.8.0"},
    {"name": "livewire/livewire", "version": "v3.5.1"},
    {"name": "filament/filament", "version": "v3.2.80"}
  ],
  "packages-dev": [
    {"name": "laravel/telescope", "version": "v5.2.0"}
  ]
}`
	files["vendor/composer/installed.json"] = `{
  "packages": [
    {"name": "laravel/framework", "version": "v11.8.0"},
    {"name": "livewire/livewire", "version": "v3.5.1"},
    {"name": "filament/filament", "version": "v3.2.80"}
  ]
}`

	// Controllers with realistic patterns
	for i := 0; i < 10; i++ {
		files[fmt.Sprintf("app/Http/Controllers/Controller%d.php", i)] = fmt.Sprintf(
			"<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\nclass Controller%d extends Controller {\n  public function index(Request $request) {\n    return view('welcome');\n  }\n}\n", i)
	}

	// Models
	for i := 0; i < 5; i++ {
		files[fmt.Sprintf("app/Models/Model%d.php", i)] = fmt.Sprintf(
			"<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Model%d extends Model {\n  protected $fillable = ['name', 'email'];\n}\n", i)
	}

	// Migrations
	for i := 0; i < 8; i++ {
		files[fmt.Sprintf("database/migrations/2024_01_%02d_create_table_%d.php", i, i)] = fmt.Sprintf(
			"<?php\nuse Illuminate\\Database\\Migrations\\Migration;\nuse Illuminate\\Database\\Schema\\Blueprint;\nreturn new class extends Migration {\n  public function up() {\n    Schema::create('table_%d', function (Blueprint $table) {\n      $table->id();\n      $table->timestamps();\n    });\n  }\n};\n", i)
	}

	// Write all files
	for path, content := range files {
		fullPath := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			b.Fatalf("MkdirAll for %q error = %v", path, err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
			b.Fatalf("WriteFile(%q) error = %v", path, err)
		}
	}

	// Set realistic permissions
	_ = os.Chmod(filepath.Join(root, ".env"), 0o640)
	_ = os.Chmod(filepath.Join(root, "bootstrap/cache/config.php"), 0o640)

	return root
}

func BenchmarkDiscoverSingleApp(b *testing.B) {
	dir := b.TempDir()
	appRoot := benchLaravelApp(b, dir, "app1")

	service := newTestSnapshotService()
	ctx := context.Background()
	config := model.AuditConfig{
		Scope:   model.ScanScopeApp,
		AppPath: appRoot,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		snapshot, unknowns, err := service.Discover(ctx, model.ExecutionContext{Config: config})
		if err != nil {
			b.Fatal(err)
		}
		if len(snapshot.Apps) != 1 {
			b.Fatalf("expected 1 app, got %d", len(snapshot.Apps))
		}
		_ = unknowns
	}
}

func BenchmarkDiscoverMultipleApps(b *testing.B) {
	dir := b.TempDir()
	for i := 0; i < 5; i++ {
		benchLaravelApp(b, dir, fmt.Sprintf("app%d", i))
	}

	service := newTestSnapshotService()
	ctx := context.Background()
	config := model.AuditConfig{
		Scope:     model.ScanScopeAuto,
		ScanRoots: []string{dir},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		snapshot, _, err := service.Discover(ctx, model.ExecutionContext{Config: config})
		if err != nil {
			b.Fatal(err)
		}
		if len(snapshot.Apps) != 5 {
			b.Fatalf("expected 5 apps, got %d", len(snapshot.Apps))
		}
	}
}

func BenchmarkInspectLaravelApplication(b *testing.B) {
	dir := b.TempDir()
	appRoot := benchLaravelApp(b, dir, "app")

	service := newTestSnapshotService()
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		app, unknowns, isApp := service.inspectLaravelApplication(ctx, appRoot)
		if !isApp {
			b.Fatal("expected valid Laravel app")
		}
		_ = app
		_ = unknowns
	}
}

func BenchmarkCollectApplicationMetadata(b *testing.B) {
	dir := b.TempDir()
	appRoot := benchLaravelApp(b, dir, "app")

	service := newTestSnapshotService()
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_, keyPaths, _, _, _, _, unknowns := service.collectApplicationMetadata(ctx, appRoot, appRoot)
		if len(keyPaths) == 0 {
			b.Fatal("expected key paths")
		}
		_ = unknowns
	}
}
