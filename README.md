Google Auth Bundle
==================

Implementation of common authentication logic

Installation
------------

Get Google App id and secret at https://console.developers.google.com/apis/credentials

Add env vars:

* `GOOGLE_AUTH_APP_ID`: from Google Console
* `GOOGLE_AUTH_APP_SECRET`: from Google Console
* `GOOGLE_AUTH_DOMAIN`: which domain is allowed to login; empty if all domains
* `GOOGLE_AUTH_USERS`: which users should be autoactivated; empty if no users
* `GOOGLE_AUTH_ADMINS`: which users should be autoactivated as admins; empty if none

Or add parameters to `config/services.yaml`

```yaml
parameters:
    google_auth_app_id:     something.apps.googleusercontent.com
    google_auth_app_secret: your_secret
    google_auth_domain:     yourdomain.com
    google_auth_users:      user1,user2
    google_auth_admins:     admin1,admin2
```

Install

```sh
composer require gupalo/google-auth-bundle
```

2) Check that **GoogleAuthBundle** and **KnpUOAuth2ClientBundle** are in `config/bundles.php`

```php
KnpU\OAuth2ClientBundle\KnpUOAuth2ClientBundle::class => ['all' => true],
Gupalo\GoogleAuthBundle\GoogleAuthBundle::class => ['all' => true],
```

3) Set `config/packages/security.yaml`

```yaml
security:
    encoders:
        Symfony\Component\Security\Core\User\User:
            algorithm: bcrypt

    # http://symfony.com/doc/current/book/security.html#where-do-users-come-from-user-providers
    providers:
        database_users:
            entity: { class: 'Gupalo\GoogleAuthBundle\Entity\User', property: username }
        api_key_user_provider:
            id: google_auth.security.api_key_user_provider

    firewalls:
        dev:
            pattern:  ^/(_(profiler|wdt)|css|images|js)/
            security: false
        api:
            pattern: ^/api/
            stateless: true
            simple_preauth:
                authenticator: google_auth.security.api_key_authenticator
            provider: api_key_user_provider
        main:
            pattern: ^/
            logout:
                path: google_auth_security_logout
                target: homepage
            anonymous:    true
            guard:
                authenticators:
                    - google_auth.security.google_authenticator
                entry_point: google_auth.security.google_authenticator
            remember_me:
                secret: "%secret%"
                lifetime: 31536000 # 365 days in seconds
                path: /
                domain: ~ # Defaults to the current domain from $_SERVER
                #always_remember_me: true
    access_control:
        - { path: ^/auth/login, role: IS_AUTHENTICATED_ANONYMOUSLY }
        - { path: ^/, roles: ROLE_USER }
```

4) Enable GoogleAuthBundle routing. Add to `app/config/routes/google_auth.yaml`

```yaml
google_auth:
    resource: "@GoogleAuthBundle/Resources/config/routing/routing.yaml"
```

5) Update your database schema
