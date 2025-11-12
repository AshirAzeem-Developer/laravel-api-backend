<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
use Exception;

class AuthController extends Controller
{
    /**
     * Handle user registration.
     */
    public function register(Request $request)
    {
        try {
            // 1. Validation check (Handled by Laravel automatically, returns 422 Unprocessable Entity)
            $request->validate([
                'name' => 'required|string|max:255',
                'email' => 'required|string|email|max:255|unique:users',
                'password' => 'required|string|min:8|confirmed',
            ]);

            // 2. Creation logic
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]);

            // 3. Token generation
            $token = $user->createToken('auth_token')->plainTextToken;

            // 4. Success response (201 Created)
            return response()->json([
                'status' => 'success',
                'message' => 'User successfully registered.',
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                ],
                'access_token' => $token,
                'token_type' => 'Bearer',
            ], 201);
        } catch (ValidationException $e) {
            // Laravel's default handling for ValidationException already returns 422 with error details
            throw $e;
        } catch (Exception $e) {
            // Catch any unexpected server errors (500 Internal Server Error)
            return response()->json([
                'status' => 'error',
                'message' => 'Registration failed due to a server error.',
                'details' => $e->getMessage() // Optional: include for debugging in non-production environments
            ], 500);
        }
    }

    /**
     * Handle user login.
     */
    public function login(Request $request)
    {
        try {
            // 1. Validation check
            $request->validate([
                'email' => 'required|string|email',
                'password' => 'required|string',
            ]);

            // 2. Authentication attempt
            if (!Auth::attempt($request->only('email', 'password'))) {
                // Throw a specific ValidationException for credential errors (Returns 422 Unprocessable Entity)
                throw ValidationException::withMessages([
                    'email' => ['The provided credentials are incorrect or the account does not exist.'],
                ]);
            }

            $user = $request->user();

            // 3. Token generation (Optional: delete old tokens for a clean session)
            $user->tokens()->delete();
            $token = $user->createToken('auth_token')->plainTextToken;

            // 4. Success response (200 OK)
            return response()->json([
                'status' => 'success',
                'message' => 'Login successful.',
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                ],
                'access_token' => $token,
                'token_type' => 'Bearer',
            ]);
        } catch (ValidationException $e) {
            // Let Laravel handle the 422 response
            throw $e;
        } catch (Exception $e) {
            // Catch any unexpected server errors (500 Internal Server Error)
            return response()->json([
                'status' => 'error',
                'message' => 'Login failed due to a server error.',
                'details' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * Handle user logout (revokes current token).
     */
    public function logout(Request $request)
    {
        // This is protected by 'auth:sanctum', so $request->user() is guaranteed to exist.
        try {
            $request->user()->currentAccessToken()->delete();

            return response()->json([
                'status' => 'success',
                'message' => 'Successfully logged out and token revoked.'
            ]); // Default status is 200 OK

        } catch (Exception $e) {
            // Handle the case where the token might have already been revoked or other issues
            return response()->json([
                'status' => 'error',
                'message' => 'Logout failed.',
                'details' => 'Could not revoke current token.'
            ], 400); // 400 Bad Request or 500 Server Error, depending on the cause
        }
    }

    /**
     * Get the authenticated user's details.
     */
    public function user(Request $request)
    {
        // This is protected by 'auth:sanctum', automatically returning 401 if unauthorized
        $user = $request->user();

        return response()->json([
            'status' => 'success',
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'created_at' => $user->created_at->toDateTimeString(),
            ]
        ]);
    }
}
