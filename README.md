Google Auth Bundle
==================

Implementation of common authentication logic

Installation
------------

Get Google App id and secret at https://console.developers.google.com/apis/credentials

Add env vars:

* `GOOGLE_AUTH_APP_ID`: from Google Console
* `GOOGLE_AUTH_APP_SECRET`: from Google Console
* `GOOGLE_AUTH_DOMAIN`: which domain is allowed to login; "*" if all domains; 'user.dev' to skip google auth and login all as ROLE_USER
* `GOOGLE_AUTH_USERS`: which users should be autoactivated; empty if no users
* `GOOGLE_AUTH_ADMINS`: which users should be autoactivated as admins; empty if none
* `GOOGLE_AUTH_DEFAULT_APIKEY`: set if you want to autocreate "api@example.com" user with this key

And create `config/packages/google_auth.yaml`

```yaml
parameters:
    env(GOOGLE_AUTH_APP_ID): something.apps.googleusercontent.com
    env(GOOGLE_AUTH_APP_SECRET): your_secret
    env(GOOGLE_AUTH_DOMAIN): "*"
    env(GOOGLE_AUTH_USERS): user1,user2
    env(GOOGLE_AUTH_ADMINS): user1,user2
    env(GOOGLE_AUTH_DEFAULT_APIKEY): ''

    google_auth_app_id: '%env(string:GOOGLE_AUTH_APP_ID)%'
    google_auth_app_secret: '%env(string:GOOGLE_AUTH_APP_SECRET)%'
    google_auth_domain: '%env(string:GOOGLE_AUTH_DOMAIN)%'
    google_auth_users: '%env(string:GOOGLE_AUTH_USERS)%'
    google_auth_admins: '%env(string:GOOGLE_AUTH_ADMINS)%'
    google_auth_default_apikey: '%env(string:GOOGLE_AUTH_DEFAULT_APIKEY)%'
```

Install

```sh
composer require gupalo/google-auth-bundle
```

2) Check that **GoogleAuthBundle** and **KnpUOAuth2ClientBundle** are in `config/bundles.php`

```
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

    firewalls:
        dev:
            pattern:  ^/(_(profiler|wdt)|css|images|js)/
            security: false
        main:
            pattern: ^/
            logout:
                path: google_auth_security_logout
                target: homepage
            anonymous: true
            guard:
                authenticators: ['google_auth.security.google_authenticator']
                entry_point: google_auth.security.google_authenticator
            provider: database_users
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


Dev
---

Set to GOOGLE_AUTH_DOMAIN to one of the values below for dev environment

* user.dev - to login as [User::ROLE_USER]
* manager.dev - [User::ROLE_MANAGER]
* admin.dev - [User::ROLE_ADMIN]
* user-admin.dev - [User::ROLE_USER, User::ROLE_ADMIN]
