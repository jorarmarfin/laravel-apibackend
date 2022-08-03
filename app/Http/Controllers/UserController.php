<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class UserController extends Controller
{
    public function userRegister(Request $request)
    {
        $user = User::create([
            'name'=> $request->get('name'),
            'email'=> $request->get('email'),
            'password'=> Hash::make($request->get('password')),
        ]);
        $token = $user->createToken('auth_token')->plainTextToken;
        return response()->json([
            'api'=>'RegisterUser',
            'access_token'=>$token,
            'token_type'=>'Bearer',
        ]);
        
    }

    public function login(Request $request)
    {
        if (Auth::attempt($request->only(['email','password']))) {
            $token = Auth::user()->createToken('auth_token')->plainTextToken;
            return response()->json([
                'auth'=>'Success',
                'token'=>$token,
                'type_auth'=>'Bearer',
            ])->setStatusCode(200);
        }else{
            return response()->json([
                'auth'=>'Error',
                'message'=>'Las credenciales enviadas no son correctas',
            ])->setStatusCode(401);

        }
    }
    public function logout(Request $request)
    {
        if (Auth::attempt($request->only(['email','password']))) {
            Auth::user()->tokens()->delete();
            return response()->json([
                'auth'=>'Success',
                'message'=>'Los token para este usuario se han eliminado',
            ])->setStatusCode(200);
        }else{
            return response()->json([
                'auth'=>'Error',
                'message'=>'Las credenciales enviadas no son correctas',
            ])->setStatusCode(401);

        }
    }
}
