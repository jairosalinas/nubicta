<?php

namespace App\Http\Middleware;

use App\Models\User;
use App\Services\Sales\CollectionAutomation;
use App\Support\CurrentCompany;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;

/** API pública /api/v1: llave "Bearer" generada en Configuración > Credenciales de integración (API). */
class AuthenticateApiToken
{
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->bearerToken();
        $row = $token ? DB::table('api_tokens')->where('token', hash('sha256', $token))->whereNull('revoked_at')->first() : null;
        if (! $row) {
            return response()->json(['message' => 'Llave de acceso inválida o revocada.'], 401);
        }
        // Tokens must remain bound to an active user from the same company.
        // A deleted, disabled or reassigned user must never authorize API calls.
        $user = User::query()->find($row->user_id);
        if (! $user || ! $user->active || (int) $user->company_id !== (int) $row->company_id) {
            return response()->json(['message' => 'La llave no pertenece a un usuario activo autorizado.'], 401);
        }

        $settings = CollectionAutomation::settings('api', $row->company_id);
        if (! $settings['enabled']) {
            return response()->json(['message' => 'La API está deshabilitada en la configuración de la empresa.'], 403);
        }
        $ips = array_filter(array_map('trim', explode(',', (string) $settings['allowed_ips'])));
        if ($ips && ! in_array($request->ip(), $ips, true)) {
            return response()->json(['message' => "La IP {$request->ip()} no está autorizada."], 403);
        }
        if (! $request->isMethodSafe() && $settings['scopes'] !== 'Lectura y escritura') {
            return response()->json(['message' => 'La llave solo tiene permiso de lectura.'], 403);
        }
        CurrentCompany::set($row->company_id);
        Auth::setUser($user);
        DB::table('api_tokens')->where('id', $row->id)->update(['last_used_at' => now(), 'last_ip' => $request->ip()]);

        return $next($request);
    }
}
