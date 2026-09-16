<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck\Tests\Laravel;

use DarkStrata\CredentialCheck\Client;
use DarkStrata\CredentialCheck\Constants;
use DarkStrata\CredentialCheck\Crypto;
use DarkStrata\CredentialCheck\Laravel\CompromisedCredentialDetected;
use DarkStrata\CredentialCheck\Laravel\CompromisedCredentialException;
use DarkStrata\CredentialCheck\Laravel\DarkStrataServiceProvider;
use DarkStrata\CredentialCheck\Laravel\NotCompromisedCredential;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Validator;
use Orchestra\Testbench\TestCase;

final class LaravelTest extends TestCase
{
    private const KEY = 'ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789';
    private const EMAIL = 'user@example.com';
    private const PASSWORD = 'password123';

    private int $requests = 0;

    protected function getPackageProviders($app): array
    {
        return [DarkStrataServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('darkstrata.api_key', 'test-key');
        $app['config']->set('auth.providers.users.driver', 'array');
        Auth::provider('array', fn() => new class implements UserProvider {
            public function retrieveById($identifier) { return null; }
            public function retrieveByToken($identifier, $token) { return null; }
            public function updateRememberToken(Authenticatable $user, $token) {}
            public function retrieveByCredentials(array $credentials) { return new GenericUser(['id' => 42, 'email' => $credentials['email']]); }
            public function validateCredentials(Authenticatable $user, array $credentials) { return $credentials['password'] === 'password123'; }
            public function rehashPasswordIfRequired(Authenticatable $user, array $credentials, bool $force = false) {}
        });
    }

    /** Swap in a client whose API says every hash in $compromised is breached. Pass a status to fail instead. */
    private function api($compromised = [], int $status = 200): void
    {
        $this->requests = 0;
        $hmacs = array_map(fn($h) => Crypto::hmacSha256($h, self::KEY), $compromised);
        $this->app->instance(Client::class, new Client([
            'apiKey' => 'test-key',
            'retries' => 0,
            'transport' => function () use ($hmacs, $status): array {
                $this->requests++;
                return [$status, [
                    'x-hmac-key' => self::KEY,
                    'x-time-window' => (string) intdiv(time(), Constants::TIME_WINDOW_SECONDS),
                ], json_encode($hmacs)];
            },
        ]));
    }

    private function hash(): string
    {
        return Crypto::hashCredential(self::EMAIL, self::PASSWORD);
    }

    public function testCleanLoginSucceeds(): void
    {
        $this->api([]);
        self::assertTrue(Auth::attempt(['email' => self::EMAIL, 'password' => self::PASSWORD]));
        self::assertSame(1, $this->requests);
    }

    public function testWrongPasswordMakesNoApiCall(): void
    {
        $this->api([]);
        self::assertFalse(Auth::attempt(['email' => self::EMAIL, 'password' => 'wrong']));
        self::assertSame(0, $this->requests);
    }

    public function testCompromisedLoginIsDeniedAndEventDispatched(): void
    {
        $this->api([$this->hash()]);
        Event::fake([CompromisedCredentialDetected::class]);

        try {
            Auth::attempt(['email' => self::EMAIL, 'password' => self::PASSWORD]);
            self::fail('expected CompromisedCredentialException');
        } catch (CompromisedCredentialException $e) {
            self::assertSame(config('darkstrata.messages.login'), $e->errors()['email'][0]);
        }
        self::assertFalse(Auth::check());
        Event::assertDispatched(CompromisedCredentialDetected::class, fn($e) => $e->source === 'login' && $e->email === self::EMAIL && $e->userId === 42);
    }

    public function testWarnActionAllowsLogin(): void
    {
        config(['darkstrata.login_action' => 'warn']);
        $this->api([$this->hash()]);
        self::assertTrue(Auth::attempt(['email' => self::EMAIL, 'password' => self::PASSWORD]));
    }

    public function testFailOpen(): void
    {
        $this->api([], 500);
        self::assertTrue(Auth::attempt(['email' => self::EMAIL, 'password' => self::PASSWORD]));

        config(['darkstrata.fail_open' => false]);
        $this->expectException(\DarkStrata\CredentialCheck\Exception\ApiException::class);
        // Different email: the first result is memoised for the request
        Auth::attempt(['email' => 'other@example.com', 'password' => self::PASSWORD]);
    }

    public function testPasswordRule(): void
    {
        $this->api([$this->hash()]);
        $rules = ['email' => 'required', 'password' => ['required', new NotCompromisedCredential()]];

        $v = Validator::make(['email' => self::EMAIL, 'password' => self::PASSWORD], $rules);
        self::assertTrue($v->fails());
        self::assertSame(config('darkstrata.messages.password'), $v->errors()->first('password'));

        $v = Validator::make(['email' => self::EMAIL, 'password' => 'something-else'], $rules);
        self::assertTrue($v->passes());

        // Explicit email for forms without an email field
        $v = Validator::make(['password' => self::PASSWORD], ['password' => [new NotCompromisedCredential(self::EMAIL)]]);
        self::assertTrue($v->fails());

        config(['darkstrata.validate_passwords' => false]);
        $v = Validator::make(['email' => self::EMAIL, 'password' => self::PASSWORD], $rules);
        self::assertTrue($v->passes());
    }

    public function testCheckCommand(): void
    {
        $this->api([]);
        $this->artisan('darkstrata:check')->assertSuccessful();

        $this->api([], 401);
        $this->artisan('darkstrata:check')->assertFailed();
    }
}
