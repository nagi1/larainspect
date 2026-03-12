# 04A Framework False-Positive Reduction

## Goal

Reduce noisy Laravel, Livewire, and Filament heuristic findings before expanding framework coverage further.

## Scope Note

- This phase now covers the existing Laravel, Livewire, Filament, Fortify, and InertiaJS heuristics.
- `forage` is still undefined in the current codebase and task docs, so it should not be added through broad string matching until the intended package or framework target is named explicitly.

## Verified False-Positive Classes

- `laravel.csrf.except_all` can fire on any `VerifyCsrfToken.php` or `bootstrap/app.php` file that contains `$except = [` or `validateCsrfTokens(except:` plus any `*` anywhere in the file, including docblocks and comments. The current matcher never proves the wildcard is actually inside the CSRF exclusion list. References: [internal/discovery/framework_source_scan.go](/Users/nagi/code/larainspect/internal/discovery/framework_source_scan.go#L207), [internal/checks/framework_heuristics.go](/Users/nagi/code/larainspect/internal/checks/framework_heuristics.go#L38).
- Laravel route heuristics treat raw `'/admin'`, `"/admin"`, and `Route::get('login'` substrings as security signals. Redirect targets, comments, external URLs, or dead code in `routes/web.php` and `routes/api.php` can therefore trigger `admin_route_without_auth_signal`, `route_without_throttle_signal`, and `admin_routes_in_api_file` findings. References: [internal/discovery/framework_source_scan.go](/Users/nagi/code/larainspect/internal/discovery/framework_source_scan.go#L232), [internal/checks/framework_heuristics.go](/Users/nagi/code/larainspect/internal/checks/framework_heuristics.go#L94).
- `laravel.session.secure_cookie_false` reports source defaults from `config/session.php`, not the effective runtime value. Apps that set `SESSION_SECURE_COOKIE=true` in the environment or config cache will still be reported. Reference: [internal/discovery/framework_source_scan.go](/Users/nagi/code/larainspect/internal/discovery/framework_source_scan.go#L216).
- `livewire.temporary_upload.public_directory` only requires `temporary_file_upload`, `'directory' =>`, and any `public` token anywhere in `config/livewire.php`. Unrelated comments or other config strings can make `livewire_temporary_uploads_public` fire without a public temporary directory actually being configured. References: [internal/discovery/framework_source_scan.go](/Users/nagi/code/larainspect/internal/discovery/framework_source_scan.go#L276), [internal/checks/framework_heuristics.go](/Users/nagi/code/larainspect/internal/checks/framework_heuristics.go#L156).
- `looksLikeLivewireComponent` accepts any scanned PHP file containing `Livewire\\Component`, and `livewireSensitivePublicPropertyPattern` scans the raw file body for `public $tenant_id`-style text. Providers, helpers, or comments can therefore be misclassified as Livewire components and feed downstream unlocked-property or missing-authorization findings. References: [internal/discovery/framework_source_scan.go](/Users/nagi/code/larainspect/internal/discovery/framework_source_scan.go#L288), [internal/discovery/framework_source_scan.go](/Users/nagi/code/larainspect/internal/discovery/framework_source_scan.go#L328), [internal/discovery/framework_source_scan.go](/Users/nagi/code/larainspect/internal/discovery/framework_source_scan.go#L414).
- Livewire missing-signal findings only accept validation and authorization signals that exist in the same component file. Components that delegate validation to form objects, traits, actions, Volt files, or policies still trigger `livewire_upload_validation_missing_signal` and `livewire_mutation_without_authorization_signal`. References: [internal/checks/framework_heuristics.go](/Users/nagi/code/larainspect/internal/checks/framework_heuristics.go#L227), [internal/checks/framework_heuristics.go](/Users/nagi/code/larainspect/internal/checks/framework_heuristics.go#L281).
- `filament_panel_public_admin_path` assumes `->path('admin')` is risky unless the same file also contains `->authMiddleware(` or `Authenticate::class`. Default Filament auth flows that rely on panel login setup, auth guards, middleware aliases, or package defaults are not recognized and will be reported as exposed. References: [internal/discovery/framework_source_scan.go](/Users/nagi/code/larainspect/internal/discovery/framework_source_scan.go#L371), [internal/checks/framework_heuristics.go](/Users/nagi/code/larainspect/internal/checks/framework_heuristics.go#L308).
- Filament missing-signal findings infer missing policy, tenancy, and MFA controls from narrow same-file string checks. Auto-discovered Laravel policies, tenant scoping outside the resource, external auth providers, or MFA enforced outside the panel provider still produce `filament_policy_signal_missing`, `filament_tenant_signal_missing`, and `filament_mfa_signal_missing`. References: [internal/discovery/framework_source_scan.go](/Users/nagi/code/larainspect/internal/discovery/framework_source_scan.go#L379), [internal/discovery/framework_source_scan.go](/Users/nagi/code/larainspect/internal/discovery/framework_source_scan.go#L390), [internal/checks/framework_heuristics.go](/Users/nagi/code/larainspect/internal/checks/framework_heuristics.go#L190), [internal/checks/framework_heuristics.go](/Users/nagi/code/larainspect/internal/checks/framework_heuristics.go#L334), [internal/checks/framework_heuristics.go](/Users/nagi/code/larainspect/internal/checks/framework_heuristics.go#L361).
- `filament.resource.sensitive_field` treats any `TextInput::make('password')`, `TextColumn::make('password')`, or `Toggle::make('is_admin')` as an exposure signal. Create-only password inputs, write-only fields, hidden columns, or explicitly authorized privilege toggles are currently indistinguishable from real exposure. Reference: [internal/discovery/framework_source_scan.go](/Users/nagi/code/larainspect/internal/discovery/framework_source_scan.go#L402).

## Tasks

- Replace comment-blind substring matching with token-aware or AST-aware extraction for PHP code paths where the current logic can be satisfied by comments, docblocks, or unrelated string literals.
- Narrow Laravel route evidence to actual route declarations and route-group configuration instead of any matching substring in the file body.
- Cross-check runtime-backed config heuristics against effective values when the snapshot already has environment or cached-config evidence available.
- Restrict Livewire component detection to files that actually define or extend a Livewire component and ignore commented property declarations.
- Expand Livewire counter-signals to cover common delegation patterns such as form objects, traits, actions, and policy methods before emitting missing-signal findings.
- Expand Filament counter-signals to recognize panel login/auth configuration, policy auto-discovery, tenancy outside the resource file, and MFA controls outside the panel provider.
- Downgrade or suppress `filament.resource.sensitive_field` findings when the field is create-only, write-only, hidden, redacted, or otherwise explicitly constrained in the same schema definition.

## Regression Coverage Required

- Add negative discovery tests for comments, docblocks, redirects, dead-code strings, and unrelated `public` tokens in config files.
- Add fixture-backed heuristic tests that prove safe Laravel route setups, runtime-secure session configs, delegated Livewire validation, delegated Livewire authorization, default Filament panel auth, external MFA, and policy auto-discovery do not emit findings.
- Keep at least one positive test beside each new negative test so the heuristic still catches the intended risky pattern.

## Blockers To Watch

- Over-correcting into false negatives by requiring perfect semantic certainty from source-only scans.
- Pulling in a heavy PHP parser without clearly bounding performance, maintenance cost, and test coverage.
- Baking framework-version-specific assumptions into heuristics without version guards or compatibility tests.
