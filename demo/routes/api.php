<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\DemoController;
use Illuminate\Support\Facades\Route;

Route::prefix('admin')->group(function (): void {
    Route::post('/login', [AuthController::class, 'login']);
    Route::get('/debug', [AuthController::class, 'debug']);
    Route::get('/dump', [AuthController::class, 'dumpRequest']);
    Route::post('/users', [DemoController::class, 'storeUser']);
    Route::get('/reports', [DemoController::class, 'report']);
    Route::post('/uploads/code', [DemoController::class, 'uploadExecutable']);
    Route::post('/uploads/avatar', [DemoController::class, 'uploadAvatar']);
    Route::post('/uploads/import', [DemoController::class, 'uploadImport']);
    Route::post('/backups', [DemoController::class, 'backup']);
    Route::post('/dynamic-eval', [DemoController::class, 'dynamicEval']);
    Route::post('/import-payload', [DemoController::class, 'importPayload']);
});
