<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response(['errors' => $validator->errors()->all()], 422);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);

        $token = $user->createToken('auth_token')->accessToken;

        return response(['token' => $token], 200);
    }

    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        if (Auth::attempt($credentials)) {
            $token = auth()->user()->createToken('auth_token')->accessToken;
            return response(['token' => $token], 200);
        } else {
            return response(['error' => 'Invalid credentials'], 401);
        }
    }

    public function getAccessToken(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response(['errors' => $validator->errors()->all()], 422);
        }

        $credentials = $request->only('email', 'password');

        if (Auth::attempt($credentials)) {
            $token = auth()->user()->createToken('auth_token')->accessToken;
            return response(['token' => $token], 200);
        } else {
            return response(['error' => 'Invalid credentials'], 401);
        }
    }

    public function user()
    {
        $user = auth()->user();
        return response(['user' => $user], 200);
    }
    public function validateToken(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'token' => 'required',
        ]);
    
        if ($validator->fails()) {
            return response(['error' => 'Token is required'], 422);
        }
    
        $token = $request->token;

        if (Auth::guard('api')->check()) {
            return response(['valid' => true], 200);
        } else {
            return response(['valid' => false], 200);
        }
    }
    public function logout()
    {
        auth()->user()->token()->revoke();
        return response(['message' => 'Successfully logged out'], 200);
    }
    public function validate_phone(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'phone' => 'required|numeric|digits:10',
        ]);

        if ($validator->fails()) {
            return response(['errors' => $validator->errors()->all()], 422);
        }

        // Logic goes here to generate digits and sent and retrive back

        return response(['message' => 'Validation code sent successfully'], 200);
    }

    public function validate_email(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
        ]);

        if ($validator->fails()) {
            return response(['errors' => $validator->errors()->all()], 422);
        }

        // Logic goes here to generate digits and sent and retrive back

        return response(['message' => 'Validation code sent successfully'], 200);
    }
    public function validate_digits(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'digits' => 'required',
        ]);

        if ($validator->fails()) {
            return response(['errors' => $validator->errors()->all()], 422);
        }

        // Logic goes here to generate digits and and validate with generated digits

        return response(['message' => 'Successfully validated'], 200);
    }
}
