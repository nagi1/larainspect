<?php

namespace App\Http\Controllers;

use App\Http\Requests\AvatarUploadRequest;
use App\Http\Requests\ImportRequest;
use App\Http\Requests\UploadRequest;
use App\Jobs\ImportJob;
use App\Models\Report;
use App\Models\User;
use App\Services\BackupService;
use App\Services\DynamicService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class DemoController extends Controller
{
    public function __construct(
        private readonly BackupService $backupService,
        private readonly DynamicService $dynamicService,
        private readonly ImportJob $importJob,
        private readonly Report $report,
    ) {}

    public function storeUser(Request $request): JsonResponse
    {
        $user = User::create($request->all());

        return response()->json($user, 201);
    }

    public function report(Request $request): JsonResponse
    {
        return response()->json([
            'report' => $this->report->insecureSummary($request),
        ]);
    }

    public function uploadExecutable(UploadRequest $request): JsonResponse
    {
        $path = $request->file('payload')->storeAs('public/uploads', $request->file('payload')->getClientOriginalName());

        return response()->json(['stored' => $path]);
    }

    public function uploadAvatar(AvatarUploadRequest $request): JsonResponse
    {
        $path = $request->file('avatar')->storeAs('public/avatars', $request->file('avatar')->getClientOriginalName());

        return response()->json(['stored' => $path]);
    }

    public function uploadImport(ImportRequest $request): JsonResponse
    {
        $path = $request->file('archive')->storeAs('public/imports', $request->file('archive')->getClientOriginalName());

        return response()->json(['stored' => $path]);
    }

    public function backup(Request $request): JsonResponse
    {
        return response()->json([
            'command' => $this->backupService->run($request->string('name', 'nightly')->toString()),
        ]);
    }

    public function dynamicEval(Request $request): JsonResponse
    {
        return response()->json([
            'result' => $this->dynamicService->execute($request->input('code', 'return 1;')),
        ]);
    }

    public function importPayload(Request $request): JsonResponse
    {
        return response()->json([
            'payload' => $this->importJob->handle($request->input('payload', 'a:0:{}')),
        ]);
    }
}
