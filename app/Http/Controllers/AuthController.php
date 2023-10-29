<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    //validaciones al registrarse un usuario
    private $rulesRegister = array(
        'nickname' => 'required|unique:users,nickname',
        'email' => 'required|email|unique:users,email',
        'password' => 'required|min:8',
    );
    //mensages de las validaciones al registrarse un usuario
    private $messagesRegister = array(
        'nickname.required' => 'Nickname Required',
        'nickname.unique' => 'Nickname in Use',
        'email.required' => 'Email Required',
        'email.email' => 'It must be Email type',
        'email.unique' => 'Email en Use',
        'password.required' => 'Password Required',
        'password.min' => 'Minimum 8 Characters',
    );
    //validaciones al logearse un usuario
    private $rulesLogin = array(
        'email' => 'required|email',
        'password' => 'required',
    );
    //mensages de las validaciones al logearse un usuario
    private $messagesLogin = array(
        'email.required' => 'Email Required',
        'email.email' => 'It must be Email type',
        'password.required' => 'Password Required',
    );

    public function registerUser(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), $this->rulesRegister, $this->messagesRegister);

            if ($validator->fails()) {
                $messages = $validator->messages();
                return response()->json([
                    'messages' => $messages,
                ], 422);
            }

            $user = new User([
                'nickname' => $request->nickname,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]);
            $user->save();

            return response()->json([
                'message' => 'Successful Registration',
                //'access_token' => $user->createToken('auth_token')->plainTextToken;
            ], 201);
        } catch (\Throwable $th) {
            return response()->json([
                'message' => 'Error Registering',
                'error' => $th->getMessage()
            ], 500);
        }
    }

    public function loginUser(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), $this->rulesLogin, $this->messagesLogin);

            if ($validator->fails()) {
                $messages = $validator->messages();
                return response()->json([
                    'messages' => $messages,
                ], 422);
            }

            $user = User::where('email', '=', $request->email)->first();
            if (!$user) {
                return response()->json([
                    'message' => 'Unregistered user or incorrect email'
                ], 203);
            }

            if (isset($user->id)) {
                if (Hash::check($request->password, $user->password)) {
                    $token = $user->createToken('auth_token')->plainTextToken;
                    return response()->json([
                        'message' => 'Successful Login',
                        'access_token' => $token,
                    ], 200);
                } else {
                    return response()->json([
                        'message' => 'Incorrect Password',
                    ], 404);
                }
            } else {
                return response()->json([
                    'message' => 'Incorrect  Password',
                ], 404);
            }
        } catch (\Throwable $th) {
            return response()->json([
                'message' => 'Error Login',
                'error' => $th->getMessage()
            ], 500);
        }
    }

    public function logout()
    {
        try {
            auth()->user()->tokens()->delete();
            return response()->json([
                'message' => 'Successful Logout'
            ], 200);
        } catch (\Throwable $th) {
            return response()->json([
                'message' => 'Error Logout',
                'error' => $th->getMessage()
            ], 500);
        }
    }

}
