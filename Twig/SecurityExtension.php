<?php

namespace Gupalo\GoogleAuthBundle\Twig;

use Gupalo\GoogleAuthBundle\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

class SecurityExtension extends AbstractExtension
{
    private ?TokenStorageInterface $tokenStorage;

    public function __construct(?TokenStorageInterface $tokenStorage = null)
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
        $token = $this->tokenStorage ? $this->tokenStorage->getToken() : null;
        if (!$token || !$token->getUsername()) {
            return '';
        }

        /** @var User $user */
        $user = $token->getUser();

        return $user->getApiKey();
    }
}
