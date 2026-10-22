<?php

namespace Tests\Feature;

use App\Http\Controllers\ApiV1\ApiBaseController;
use App\Http\Middleware\AuthenticateApiToken;
use App\Support\CurrentCompany;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Tests\TestCase;

class ApiTokenSecurityTest extends TestCase
{
    private const TOKEN = 'test-token-for-api-security';

    protected function setUp(): void
    {
        parent::setUp();

        CurrentCompany::set(null);

        // Isolated schema: no ERP seeders, real companies or production data.
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('company_id');
            $table->string('name');
            $table->string('email');
            $table->string('password');
            $table->boolean('active');
        });

        Schema::create('api_tokens', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('company_id');
            $table->unsignedBigInteger('user_id')->nullable();
            $table->string('token', 64)->unique();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->string('last_ip')->nullable();
        });

        Schema::create('app_settings', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('company_id');
            $table->string('key');
            $table->text('value')->nullable();
        });

        DB::table('app_settings')->insert([
            'company_id' => 1,
            'key' => 'api',
            'value' => json_encode([
                'enabled' => true,
                'allowed_ips' => '',
                'scopes' => 'Lectura y escritura',
            ], JSON_THROW_ON_ERROR),
        ]);

        Route::middleware(AuthenticateApiToken::class)
            ->get('/api/v1/__security_test', fn () => response()->json([
                'authenticated' => Auth::check(),
                'company_id' => CurrentCompany::id(),
            ]));
    }

    protected function tearDown(): void
    {
        CurrentCompany::set(null);

        Schema::dropIfExists('app_settings');
        Schema::dropIfExists('api_tokens');
        Schema::dropIfExists('users');

        parent::tearDown();
    }

    public function test_token_for_deleted_user_is_rejected(): void
    {
        $this->insertToken(999);

        $this->withToken(self::TOKEN)->getJson('/api/v1/__security_test')->assertUnauthorized();
    }

    public function test_token_for_disabled_user_is_rejected(): void
    {
        $this->insertUser(10, 1, false);
        $this->insertToken(10);

        $this->withToken(self::TOKEN)->getJson('/api/v1/__security_test')->assertUnauthorized();
    }

    public function test_token_for_user_from_another_company_is_rejected(): void
    {
        $this->insertUser(10, 2, true);
        $this->insertToken(10);

        $this->withToken(self::TOKEN)->getJson('/api/v1/__security_test')->assertUnauthorized();
    }

    public function test_revoked_token_is_rejected(): void
    {
        $this->insertUser(10, 1, true);
        $this->insertToken(10, true);

        $this->withToken(self::TOKEN)->getJson('/api/v1/__security_test')->assertUnauthorized();
    }

    public function test_token_for_active_user_from_same_company_authenticates(): void
    {
        $this->insertUser(10, 1, true);
        $this->insertToken(10);

        $this->withToken(self::TOKEN)->getJson('/api/v1/__security_test')
            ->assertOk()
            ->assertJson(['authenticated' => true, 'company_id' => 1]);

        $this->assertNotNull(DB::table('api_tokens')->value('last_used_at'));
    }

    public function test_api_authorization_denies_request_without_authenticated_user(): void
    {
        $controller = new class extends ApiBaseController {
            public function checkPermission(string $permission): void
            {
                $this->authorizeApi($permission);
            }
        };

        try {
            $controller->checkPermission('terceros.crear');
            $this->fail('API access without an authenticated user must be denied.');
        } catch (HttpException $e) {
            $this->assertSame(403, $e->getStatusCode());
        }
    }

    private function insertUser(int $id, int $companyId, bool $active): void
    {
        DB::table('users')->insert([
            'id' => $id,
            'company_id' => $companyId,
            'name' => 'API test user',
            'email' => "api-test-{$id}@example.test",
            'password' => 'not-used-for-api-tokens',
            'active' => $active,
        ]);
    }

    private function insertToken(?int $userId, bool $revoked = false): void
    {
        DB::table('api_tokens')->insert([
            'company_id' => 1,
            'user_id' => $userId,
            'token' => hash('sha256', self::TOKEN),
            'revoked_at' => $revoked ? now() : null,
        ]);
    }
}
