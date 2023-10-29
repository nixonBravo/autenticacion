<?php

use App\Http\Controllers\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::post('auth/register', [AuthController::class, 'registerUser'])->name('auth.register');
Route::post('auth/login', [AuthController::class, 'loginUser'])->name('auth.login');

Route::middleware(['auth:sanctum'])->group(function () {
    Route::delete('auth/logout', [AuthController::class, 'logout'])->name('auth.logout');
});
