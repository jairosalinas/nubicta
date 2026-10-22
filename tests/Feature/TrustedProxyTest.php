<?php

namespace Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Tests\TestCase;

class TrustedProxyTest extends TestCase
{
    public function test_https_is_detected_only_when_the_request_comes_from_a_trusted_proxy(): void
    {
        config()->set('app.trusted_proxies', ['10.20.30.40']);

        Route::get('/__test_proxy_scheme', fn (Request $request) => response()->json([
            'secure' => $request->isSecure(),
            'url' => url('/login'),
        ]));

        $this->withServerVariables([
            'REMOTE_ADDR' => '10.20.30.40',
            'HTTP_HOST' => 'contabilidad.example.test',
            'HTTP_X_FORWARDED_HOST' => 'contabilidad.example.test',
            'HTTP_X_FORWARDED_PROTO' => 'https',
            'HTTP_X_FORWARDED_PORT' => '443',
            'SERVER_PORT' => '80',
        ])->get('/__test_proxy_scheme')
            ->assertOk()
            ->assertJson([
                'secure' => true,
                'url' => 'https://contabilidad.example.test/login',
            ]);
    }

    public function test_untrusted_client_cannot_force_https_with_forwarded_headers(): void
    {
        config()->set('app.trusted_proxies', ['10.20.30.40']);

        Route::get('/__test_proxy_scheme', fn (Request $request) => response()->json([
            'secure' => $request->isSecure(),
            'url' => url('/login'),
        ]));

        $this->withServerVariables([
            'REMOTE_ADDR' => '10.20.30.41',
            'HTTP_HOST' => 'contabilidad.example.test',
            'HTTP_X_FORWARDED_PROTO' => 'https',
            'HTTP_X_FORWARDED_PORT' => '443',
            'SERVER_PORT' => '80',
        ])->get('/__test_proxy_scheme')
            ->assertOk()
            ->assertJson([
                'secure' => false,
                'url' => 'http://contabilidad.example.test/login',
            ]);
    }
}
