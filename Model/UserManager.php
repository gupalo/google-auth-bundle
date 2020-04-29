<?php

namespace Gupalo\GoogleAuthBundle\Model;

use Doctrine\Persistence\ObjectManager;
use Doctrine\Persistence\ObjectRepository;
use Gupalo\GoogleAuthBundle\Entity\AbstractUser;
use Gupalo\GoogleAuthBundle\Entity\User;
use Gupalo\GoogleAuthBundle\Repository\UserRepository;

class UserManager
{
    private ObjectManager $objectManager;

    private string $class;

    /** @var ObjectRepository|UserRepository */
    private ObjectRepository $repository;

    public function __construct(ObjectManager $objectManager, string $class = User::class, ObjectRepository $repository = null)
    {
        $this->objectManager = $objectManager;
        $this->repository = $repository ?? $objectManager->getRepository($class);

        $metadata = $objectManager->getClassMetadata($class);
        $this->class = $metadata->getName();
    }

    public function getClass(): string
    {
        return $this->class;
    }

    public function saveUser(AbstractUser $user): void
    {
        $this->objectManager->persist($user);
        $this->objectManager->flush();
    }

    public function createUser(): AbstractUser
    {
        $class = $this->getClass();

        return new $class;
    }

    public function countEnabled(): int
    {
        return $this->repository->count(['enabled' => true]);
    }

    public function findOneByGoogleId(string $googleId): ?AbstractUser
    {
        return $this->repository->findOneByGoogleId($googleId);
    }

    public function findOneByEmail(string $email): ?AbstractUser
    {
        return $this->repository->findOneByEmail($email);
    }

    public function findOneByUsername(string $username): ?AbstractUser
    {
        return $this->repository->findOneByUsername($username);
    }

    public function findOneByApiKey(string $email): ?AbstractUser
    {
        return $this->repository->findOneByApiKey($email);
    }
}
