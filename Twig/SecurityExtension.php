<?php

namespace Gupalo\GoogleAuthBundle\Twig;

use Gupalo\GoogleAuthBundle\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

class SecurityExtension extends AbstractExtension
{
    private TokenStorageInterface $tokenStorage;

    public function __construct(TokenStorageInterface $tokenStorage)
    {
        $this->tokenStorage = $tokenStorage;
    }

    public function getFunctions(): array
    {
        return [
            new TwigFunction('api_key', [$this, 'apiKey']),
        ];
    }

    public function apiKey(): string
    {
        $token = $this->tokenStorage->getToken();
        if (!$token) {
            return '';
        }
        $username = $token->getUsername();
        if (!$username) {
            return '';
        }

        /** @var User $user */
        $user = $token->getUser();

        return $user->getApiKey();
    }
}
