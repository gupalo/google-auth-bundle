<?php

namespace Gupalo\GoogleAuthBundle\Security;

use Gupalo\GoogleAuthBundle\Entity\User;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

class ApiKeyAuthenticator extends AbstractGuardAuthenticator
{
    /**
     * Called on every request to decide if this authenticator should be
     * used for the request. Returning false will cause this authenticator
     * to be skipped.
     *
     * @param Request $request
     * @return bool
     */
    public function supports(Request $request): bool
    {
        $apiKey = $this->getApiKeyFromRequest($request);

        return (bool)$apiKey;
    }

    /**
     * Called on every request. Return whatever credentials you want to
     * be passed to getUser() as $credentials.
     *
     * @param Request $request
     * @return array
     */
    public function getCredentials(Request $request): array
    {
        return [
            'token' => $this->getApiKeyFromRequest($request),
        ];
    }

    public function getUser($credentials, UserProviderInterface $userProvider): ?UserInterface
    {
        $apiToken = $credentials['token'];

        if ($apiToken === null) {
            return null;
        }

        if ($apiToken === 'cli') {
            return (new User())
                ->setEnabled(true)
                ->setRoles([User::ROLE_USER, User::ROLE_ADMIN])
                ->setUsername('cli');
        }

        $user = $userProvider->loadUserByApiKey($apiToken);
        if ($user instanceof User) {
            $user->setIsApiAuth(true);
        }

        return $user;
    }

    public function checkCredentials($credentials, UserInterface $user): bool
    {
        // check credentials - e.g. make sure the password is valid
        // no credential check is needed in this case

        // return true to cause authentication success
        return true;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey): void
    {
        // on success, let the request continue
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): JsonResponse
    {
        $data = [
            'message' => strtr($exception->getMessageKey(), $exception->getMessageData()),

            // or to translate this message
            // $this->translator->trans($exception->getMessageKey(), $exception->getMessageData())
        ];

        return new JsonResponse($data, Response::HTTP_FORBIDDEN);
    }

    /**
     * Called when authentication is needed, but it's not sent
     *
     * @param Request $request
     * @param AuthenticationException|null $authException
     * @return JsonResponse
     */
    public function start(Request $request, AuthenticationException $authException = null): JsonResponse
    {
        $data = [
            // you might translate this message
            'message' => 'Authentication Required',
        ];

        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
    }

    public function supportsRememberMe(): bool
    {
        return false;
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

        return $apiKey;
    }

    private function isCli(): bool
    {
        return (strpos(PHP_SAPI, 'cli') === 0);
    }
}
