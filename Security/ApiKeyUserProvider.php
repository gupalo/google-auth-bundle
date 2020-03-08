<?php

namespace Gupalo\GoogleAuthBundle\Security;

use Doctrine\Persistence\ObjectManager;
use Doctrine\Persistence\ObjectRepository;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Gupalo\GoogleAuthBundle\Entity\User;
use Symfony\Component\Security\Core\User\UserInterface;

class ApiKeyUserProvider implements UserProviderInterface
{
    /** @var string */
    private $class;

    /** @var ObjectRepository */
    private $repository;

    public function __construct(ObjectManager $em, string $class = User::class)
    {
        $this->class = $class;
        $this->repository = $em->getRepository($class);
    }

    public function loadUserByApiKey($apiKey): ?User
    {
        $apiKey = trim($apiKey);
        if (!preg_match('#^[A-Za-z0-9]{8,}$#', $apiKey)) {
            return null;
        }

        /** @var User[] $users */
        $users = $this->repository->findBy(['apiKey' => $apiKey]);

        return (count($users) === 1) ? $users[0] : null;
    }

    public function loadUserByUsername($username)
    {
        return $this->repository->findOneBy(['username' => $username]);
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        // $user is the User that you set in the token inside authenticateToken()
        // after it has been deserialized from the session

        // you might use $user to query the database for a fresh user
        // $id = $user->getId();
        // use $id to make a query

        // if you are *not* reading from a database and are just creating
        // a User object (like in this example), you can just return it
        return $user;
    }

    public function supportsClass($class): bool
    {
        return $this->class === $class;
    }
}
