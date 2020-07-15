<?php

/** @noinspection PhpParamsInspection */
/** @noinspection PhpUndefinedMethodInspection */

namespace Gupalo\GoogleAuthBundle\Tests\Model;

use Doctrine\Persistence\Mapping\ClassMetadata;
use Doctrine\Persistence\ObjectManager;
use Gupalo\GoogleAuthBundle\Entity\User;
use Gupalo\GoogleAuthBundle\Model\UserManager;
use Gupalo\GoogleAuthBundle\Repository\UserRepository;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;

class TestUser extends User
{
}

/**
 * @covers \Gupalo\GoogleAuthBundle\Model\UserManager
 */
class UserManagerTest extends TestCase
{
    use ProphecyTrait;

    private const USER_CLASS = TestUser::class;

    private UserManager $userManager;

    /** @var ObjectManager */
    private $om;

    /** @var UserRepository */
    private $repository;

    public function setUp(): void
    {
        $this->om = $this->prophesize(ObjectManager::class);
        $this->repository = $this->prophesize(UserRepository::class);
        $class = $this->prophesize(ClassMetadata::class);

        $this->om->getRepository(self::USER_CLASS)->shouldBeCalledTimes(1)->willReturn($this->repository);
        $this->om->getClassMetadata(self::USER_CLASS)->shouldBeCalledTimes(1)->willReturn($class);
        $class->getName()->willReturn(self::USER_CLASS);

        $this->userManager = new UserManager($this->om->reveal(), self::USER_CLASS);
    }

    public function testGetClass(): void
    {
        self::assertEquals(self::USER_CLASS, $this->userManager->getClass());
    }

    public function testCreateUser(): void
    {
        $user = $this->userManager->createUser();
        self::assertEquals(time(), $user->getCreatedAt()->getTimestamp(), 2);
        self::assertEquals(time(), $user->getLastActiveAt()->getTimestamp(), 2);
    }

    public function testSaveUser(): void
    {
        $user = new TestUser();

        $this->om->persist($user)->shouldBeCalledTimes(1);
        $this->om->flush()->shouldBeCalledTimes(1);

        $this->userManager->saveUser($user);
    }

    public function testFindOneByGoogleId(): void
    {
        $user = new TestUser();
        $googleId = '123asd321';

        $this->repository->findOneByGoogleId($googleId)->shouldBeCalledTimes(1)->willReturn($user);

        self::assertSame($user, $this->userManager->findOneByGoogleId($googleId));
    }

    public function testFindOneByEmail(): void
    {
        $user = new TestUser();
        $email = 'email@test.com';

        $this->repository->findOneByEmail($email)->shouldBeCalledTimes(1)->willReturn($user);

        self::assertSame($user, $this->userManager->findOneByEmail($email));
    }
}
