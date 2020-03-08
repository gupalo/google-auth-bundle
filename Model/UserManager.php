<?php

namespace Gupalo\GoogleAuthBundle\Model;

use Doctrine\Persistence\ObjectManager;
use Doctrine\Persistence\ObjectRepository;
use Gupalo\GoogleAuthBundle\Entity\User;
use Gupalo\GoogleAuthBundle\Repository\UserRepository;

class UserManager
{
    private ObjectManager $objectManager;

    private string $class;

    /** @var ObjectRepository|UserRepository */
    private ObjectRepository $repository;

    public function __construct(ObjectManager $objectManager, string $class = User::class)
    {
        $this->objectManager = $objectManager;
        $this->repository = $objectManager->getRepository($class);

        $metadata = $objectManager->getClassMetadata($class);
        $this->class = $metadata->getName();
    }

    public function getClass(): string
    {
        return $this->class;
    }

    public function saveUser(User $user): void
    {
        $this->objectManager->persist($user);
        $this->objectManager->flush();
    }

    public function createUser(): User
    {
        $class = $this->getClass();

        return new $class;
    }

    public function findOneByGoogleId(string $googleId): ?User
    {
        return $this->repository->findOneByGoogleId($googleId);
    }

    public function findOneByEmail(string $email): ?User
    {
        return $this->repository->findOneByEmail($email);
    }

    public function findOneByApiKey(string $email): ?User
    {
        return $this->repository->findOneByApiKey($email);
    }
}