<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function login(Request $request): JsonResponse
    {
        $userId = $request->integer('user_id');

        Auth::loginUsingId($userId);

        return response()->json([
            'logged_in_as' => $userId,
            'token' => $request->bearerToken(),
        ]);
    }

    public function debug(): never
    {
        phpinfo();
        exit;
    }

    public function dumpRequest(Request $request): never
    {
        dump($request->all());
        dd($request->headers->all());
    }
}
