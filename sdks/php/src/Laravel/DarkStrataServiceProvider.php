<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck\Laravel;

use DarkStrata\CredentialCheck\Client;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\ServiceProvider;

final class DarkStrataServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../../config/darkstrata.php', 'darkstrata');

        $this->app->singleton(Client::class, function ($app) {
            $config = $app['config']['darkstrata'];
            return new Client([
                'apiKey' => (string) $config['api_key'],
                'baseUrl' => $config['base_url'],
            ]);
        });

        $this->app->singleton(CredentialChecker::class);
    }

    public function boot(Dispatcher $events): void
    {
        $this->publishes([__DIR__ . '/../../config/darkstrata.php' => $this->app->configPath('darkstrata.php')], 'darkstrata-config');

        if ($this->app->runningInConsole()) {
            $this->commands([CheckCommand::class]);
        }

        if (empty($this->app['config']['darkstrata.api_key'])) {
            $this->app['log']->warning('DarkStrata credential checks are disabled: no API key in config darkstrata.api_key');
            return;
        }

        if ($this->app['config']['darkstrata.check_logins']) {
            $events->subscribe(LoginSubscriber::class);
        }
    }
}
