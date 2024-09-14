<?php

use App\Http\Controllers\TodosController;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

// AUTH

Route::post('/register', function (Request $request) {
    $request->validate([
        'name' => 'required|string|max:255',
        'email' => 'required|string|email|max:255|unique:users',
        'password' => ['required'],
    ]);

    // Create a new user
    $user = User::create([
        'name' => $request->name,
        'email' => $request->email,
        'password' => Hash::make($request->password),
    ]);

    // Generate a new token for the user
    $token = $user->createToken('api-token')->plainTextToken;

    return response()->json([
        'message' => 'Registration successful',
        'user' => $user,
        'token' => $token,
    ], 201);
});

Route::post('/login', function (Request $request) {
    $request->validate([
        'email' => 'required|email',
        'password' => 'required',
    ]);

    $user = User::where('email', $request->email)->first();

    if (!$user || !Hash::check($request->password, $user->password)) {
        return response()->json(['message' => 'Invalid credentials'], 401);
    }

    // Delete previous tokens if you want to generate a fresh one each time
    $user->tokens()->delete();

    // Generate a new token
    $token = $user->createToken('api-token')->plainTextToken;

    return response()->json([
        'token' => $token,
        'message' => 'Login successful',
        'user' => $user, // Optional: return user data if needed
    ]);
});

Route::post('/logout', function (Request $request) {
    $request->user()->currentAccessToken()->delete();

    return response()->json(['message' => 'Logged out successfully']);
})->middleware('auth:sanctum');

Route::post('/profile/update', function (Request $request) {
    // Validate the request data
    $request->validate([
        'name' => 'required|string|max:255',
        'email' => 'required|string|email|max:255|unique:users,email,' . $request->user()->id,
        'password' => ['nullable'],
    ]);

    // Get the authenticated user
    $user = $request->user();

    // Update user details
    $user->name = $request->name;
    $user->email = $request->email;

    // Only update password if it's provided
    if ($request->filled('password')) {
        $user->password = Hash::make($request->password);
    }

    // Save the updated user data
    $user->save();

    return response()->json([
        'message' => 'Profile updated successfully',
        'user' => $user,
    ], 200);
})->middleware('auth:sanctum');

// Todo

Route::post('/store-todo', [TodosController::class, 'store'])->middleware('auth:sanctum');
Route::post('/update-todo', [TodosController::class, 'update'])->middleware('auth:sanctum');
Route::post('/destroy-todo', [TodosController::class, 'destroy'])->middleware('auth:sanctum');
Route::get('/show-todos', [TodosController::class, 'index'])->middleware('auth:sanctum');
Route::get('/show-todo/{todo_id}', [TodosController::class, 'show'])->middleware('auth:sanctum');
Route::get('/edit-todo/{todo_id}', [TodosController::class, 'edit'])->middleware('auth:sanctum');
