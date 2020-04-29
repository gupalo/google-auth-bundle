<?php

namespace Gupalo\GoogleAuthBundle\Repository;

use Gupalo\GoogleAuthBundle\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @method User|null find($id, $lockMode = null, $lockVersion = null)
 * @method User|null findOneBy(array $criteria, array $orderBy = null)
 * @method User[]    findAll()
 * @method User[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class UserRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry, string $entityClass = User::class)
    {
        parent::__construct($registry, $entityClass);
    }

    public function findOneByGoogleId(string $googleId): ?User
    {
        return $this->findOneBy(['googleId' => $googleId]);
    }

    public function findOneByEmail(string $email): ?User
    {
        return $this->findOneBy(['email' => $email]);
    }

    public function findOneByUsername(string $username): ?User
    {
        return $this->findOneBy(['username' => $username]);
    }

    public function findOneByApiKey(string $apiKey): ?User
    {
        return $this->findOneBy(['apiKey' => $apiKey]);
    }
}
