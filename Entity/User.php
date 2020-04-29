<?php

namespace Gupalo\GoogleAuthBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * User class
 *
 * @ORM\Entity()
 * @ORM\Table(name="user")
 */
class User extends AbstractUser
{
    public const ROLE_GUEST = 'ROLE_GUEST';
    public const ROLE_USER = 'ROLE_USER';
    public const ROLE_API = 'ROLE_API';
    public const ROLE_MANAGER = 'ROLE_MANAGER';
    public const ROLE_ADMIN = 'ROLE_ADMIN';
}
