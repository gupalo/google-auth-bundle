<?php

namespace Gupalo\GoogleAuthBundle\Security;

use DateTime;
use Exception;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
use KnpU\OAuth2ClientBundle\Security\Helper\FinishRegistrationBehavior;
use KnpU\OAuth2ClientBundle\Security\Helper\PreviousUrlHelper;
use KnpU\OAuth2ClientBundle\Security\Helper\SaveAuthFailureMessage;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Gupalo\GoogleAuthBundle\Entity\User;
use Gupalo\GoogleAuthBundle\Model\UserManager;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Throwable;

class GoogleAuthenticator extends SocialAuthenticator
{
    use PreviousUrlHelper;
    use SaveAuthFailureMessage;
    use FinishRegistrationBehavior;

    private static $rememberMe = false;

    /** @var ClientRegistry */
    private $clientRegistry;

    /** @var RouterInterface */
    private $router;

    /** @var string[] */
    private $googleDomains;

    /** @var array */
    private $allowedUsers;

    /** @var UserManager|null */
    private $userManager;

    /** @var array */
    private $adminUsers;

    /** @var string[] */
    private $allowedUsernames;

    /** @var string[] */
    private $adminUsernames;

    private ?string $defaultApiKey;

    public function __construct(
        ClientRegistry $clientRegistry,
        RouterInterface $router,
        UserManager $userManager = null,
        string $googleDomain = null,
        string $allowedUsernames = null,
        string $adminUsernames = null,
        string $defaultApiKey = null
    ) {
        $this->clientRegistry = $clientRegistry;
        $this->router = $router;
        $this->userManager = $userManager;
        $this->googleDomains = array_values(array_filter(array_map('trim', explode(',', mb_strtolower($googleDomain)))));
        $this->allowedUsernames = array_values(array_filter(array_map('trim', explode(',', mb_strtolower($allowedUsernames)))));
        $this->adminUsernames = array_values(array_filter(array_map('trim', explode(',', mb_strtolower($adminUsernames)))));
        $this->defaultApiKey = $defaultApiKey;
    }

    /**
     * @param Request $request
     * @return AccessToken|string|null
     * @throws IdentityProviderException
     */
    public function getCredentials(Request $request)
    {
        $token = $this->getApiKeyFromRequest($request);

        if (!$token) {
            try {
                $client = $this->getGoogleClient();
                $token = $client->getAccessToken();
            } catch (IdentityProviderException $e) {
                // you could parse the response to see the problem
                throw $e;
            }
        }

        return $token;
    }

    /**
     * @param AccessToken|string|null $credentials
     * @param UserProviderInterface $userProvider
     * @return User|null
     * @throws Exception
     */
    public function getUser($credentials, UserProviderInterface $userProvider): ?User
    {
        if ($credentials === null) {
            return null;
        }

        // try login via api key
        if (is_string($credentials)) {
            if ($credentials === 'cli') {
                return (new User())
                    ->setEnabled(true)
                    ->setRoles([User::ROLE_USER, User::ROLE_ADMIN])
                    ->setUsername('cli');
            }

            $user = $this->userManager->findOneByApiKey($credentials);
            if ($user instanceof User) {
                $user->setIsApiAuth(true);
            }

            return $user;
        }

        $googleClient = $this->getGoogleClient();
        $googleUser = $googleClient->fetchUserFromToken($credentials);

        // 1) have they logged in with Google before? Easy!
        $existingUser = $this->userManager->findOneByGoogleId($googleUser->getId());
        if ($existingUser) {
            return $existingUser;
        }

        // 2) do we have a matching user by email?
        $email = $googleUser->getEmail();
        $user = $this->userManager->findOneByEmail($email);

        // 3) no user? Redirect to finish registration
        if (!$user) {
            $username = preg_replace('#@.*#', '', $email);
            $domain = mb_strtolower(preg_replace('#^.*@#', '', $email));

            if (!empty($this->googleDomains) && !in_array($domain, $this->googleDomains, true)) {
                throw new AuthenticationException();
            }

            if ($this->defaultApiKey && !$this->userManager->countEnabled()) {
                $this->userManager->createUser()
                    ->setEnabled(true)
                    ->setEmail('api@example.com')
                    ->setUsername('api')
                    ->setRoles([User::ROLE_API])
                    ->setApiKey($this->defaultApiKey)
                    ->setData([]);
            }

            $user = $this->userManager->createUser()
                ->setEnabled(false)
                ->setEmail($email)
                ->setUsername($username)
                ->setRoles([User::ROLE_USER])
                ->setData([]);

            if ($this->isAllowedUsername($username)) {
                $user->setEnabled(true);
                $user->setApiKey($this->generateApiKey());
            }

            if ($this->isAdminUsername($username)) {
                $user->setRoles([User::ROLE_USER, User::ROLE_ADMIN]);
            }
        }

        if ($user && $googleUser) {
            $user
                ->setName($googleUser->getName())
                ->setFirstName($googleUser->getFirstName())
                ->setSurname($googleUser->getLastName())
                ->setPictureUrl($googleUser->getAvatar())
                ->setLocale($googleUser->getLocale())
                ->setIsEmailVerified($googleUser->toArray()['email_verified'] ?? false);
        }

        // make sure the Google user is set
        $user->setGoogleId($googleUser->getId());
        $user->setLastActiveAt(new DateTime());
        if (!$user->getRoles()) {
            $user->setRoles([User::ROLE_USER]);
        }
        if (!$user->getData()) {
            $user->setData([]);
        }
        $this->userManager->saveUser($user);

        $user->setIsApiAuth(false);

        return $user;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        if ($this->getApiKeyFromRequest($request)) {
            return new JsonResponse(['message' => strtr($exception->getMessageKey(), $exception->getMessageData())], Response::HTTP_FORBIDDEN);
        }

        $this->saveAuthenticationErrorToSession($request, $exception);
        $loginUrl = $this->router->generate('google_auth_security_logout');

        return new RedirectResponse($loginUrl);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        if ($this->getApiKeyFromRequest($request)) {
            return null;
        }

        $url = $this->getPreviousUrl($request, $providerKey);
        if (!$url) {
            try {
                $url = $this->router->generate('homepage');
            } catch (Throwable $e) {
                $url = '/';
            }
        }

        return new RedirectResponse($url);
    }

    /**
     * Called when an anonymous user tries to access an protected page.
     *
     * In our app, this is never actually called, because there is only *one* "entry_point" per firewall and in security.yml,
     * we're using app.form_login_authenticator as the entry point (so it's start() method is the one that's called).
     * @param Request $request
     * @param AuthenticationException $authException
     * @return Response
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        // not called in our app, but if it were, redirecting to the login page makes sense
        $url = $this->router->generate('google_auth_security_login');

        return new RedirectResponse($url);
    }

    /**
     * Does the authenticator support the given Request?
     *
     * If this returns false, the authenticator will be skipped.
     *
     * @param Request $request
     * @return bool
     */
    public function supports(Request $request): bool
    {
        // continue ONLY if the current ROUTE matches the check ROUTE or has api key
        return (
            $request->attributes->get('_route') === 'google_auth_connect_google_check' ||
            $this->getApiKeyFromRequest($request)
        );
    }

    public function supportsRememberMe(): bool
    {
        return self::$rememberMe;
    }

    private function getGoogleClient(): OAuth2ClientInterface
    {
        return $this->clientRegistry->getClient('google');
    }

    private function isAllowedUsername(?string $username): bool
    {
        return (
            in_array($username, $this->allowedUsernames, true) ||
            $this->isAdminUsername($username)
        );
    }

    private function isAdminUsername(?string $username): bool
    {
        return in_array($username, $this->adminUsernames, true);
    }

    private function generateApiKey(): string
    {
        try {
            $apiKey = bin2hex(random_bytes(16));
        } catch (Throwable $e) {
            $apiKey = '';
        }

        return $apiKey;
    }

    private function getApiKeyFromRequest(Request $request): ?string
    {
        $apiKey = $request->headers->get('X-Api-Key');
        if (!$apiKey) {
            $apiKey = $request->request->get('apikey');
        }
        if (!$apiKey) {
            $apiKey = $request->query->get('apikey');
        }

        if (!$apiKey && $this->isCli()) {
            return 'cli';
        }

        self::$rememberMe = ($apiKey === null);

        if (!$apiKey) {
            $apiKey = null;
        }

        return $apiKey;
    }

    private function isCli(): bool
    {
        return (strpos(PHP_SAPI, 'cli') === 0 && strpos($_SERVER['argv'][0] ?? '', 'phpunit') === false);
    }
}
