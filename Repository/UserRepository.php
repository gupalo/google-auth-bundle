<?php

namespace Gupalo\GoogleAuthBundle\Repository;

use Gupalo\GoogleAuthBundle\Entity\AbstractUser;
use Gupalo\GoogleAuthBundle\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @method AbstractUser|null find($id, $lockMode = null, $lockVersion = null)
 * @method AbstractUser|null findOneBy(array $criteria, array $orderBy = null)
 * @method AbstractUser[]    findAll()
 * @method AbstractUser[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class UserRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry, string $entityClass = User::class)
    {
        parent::__construct($registry, $entityClass);
    }

    public function findOneByGoogleId(string $googleId): ?AbstractUser
    {
        return $this->findOneBy(['googleId' => $googleId]);
    }

    public function findOneByEmail(string $email): ?AbstractUser
    {
        return $this->findOneBy(['email' => $email]);
    }

    public function findOneByUsername(string $username): ?AbstractUser
    {
        return $this->findOneBy(['username' => $username]);
    }

    public function findOneByApiKey(string $apiKey): ?AbstractUser
    {
        return $this->findOneBy(['apiKey' => $apiKey]);
    }
}
