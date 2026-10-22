<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Trusted reverse proxies
    |--------------------------------------------------------------------------
    |
    | Laravel 13's TrustProxies middleware reads "trustedproxy.proxies" when
    | handling the HTTP request, after application configuration has loaded.
    | Define only your reverse proxy IPs or CIDR ranges in TRUSTED_PROXIES.
    | Leave empty for direct access; avoid '*' on Internet-facing servers.
    |
    */
    'proxies' => array_values(array_filter(
        array_map('trim', explode(',', (string) env('TRUSTED_PROXIES', '')))
    )),
];
