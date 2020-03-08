<?php

namespace Gupalo\GoogleAuthBundle\Tests\Security;

use Doctrine\Persistence\ObjectManager;
use Doctrine\Persistence\ObjectRepository;
use Gupalo\GoogleAuthBundle\Entity\User;
use Gupalo\GoogleAuthBundle\Security\ApiKeyUserProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\ParameterBag;
use Symfony\Component\HttpFoundation\Request;

class ApiKeyUserProviderTest extends TestCase
{
    /** @var ObjectRepository */
    private $repository;

    /** @var User */
    private $user;

    /** @var ApiKeyUserProvider */
    private $userProvider;

    protected function setUp(): void
    {
        $em = $this->prophesize(ObjectManager::class);
        $this->repository = $this->prophesize(ObjectRepository::class);
        $this->user = (new User())->setUsername('user1');

        $em->getRepository(User::class)->shouldBeCalledTimes(1)->willReturn($this->repository->reveal());

        $this->userProvider = new ApiKeyUserProvider($em->reveal());
    }

    public function testLoadUserByUsername(): void
    {
        $request = $this->prophesize(Request::class);
        $headers = $this->prophesize(ParameterBag::class);
        $request->headers = $headers;

        $this->repository->findOneBy(['username' => 'user1'])->shouldBeCalledTimes(1)->willReturn($this->user);

        $user = $this->userProvider->loadUserByUsername('user1');

        $this->assertSame($user, $this->user);
    }

    public function testGetUsernameForApiKey(): void
    {
        $this->repository->findBy(['apiKey' => 'SuperKey'])->shouldBeCalledTimes(1)->willReturn([$this->user]);

        $user = $this->userProvider->loadUserByApiKey('SuperKey');

        $this->assertSame($user, $this->user);
    }

    public function testGetUsernameForApiKey_Incorrect(): void
    {
        $this->repository->findBy(['apiKey' => 'SuperKey'])->shouldBeCalledTimes(1)->willReturn([]);

        $user = $this->userProvider->loadUserByApiKey('SuperKey');

        $this->assertNull($user);
    }

    public function testRefreshUser(): void
    {
        $user = $this->userProvider->refreshUser($this->user);

        $this->assertSame($user, $this->user);
    }

    public function testSupportsClass(): void
    {
        $this->assertTrue($this->userProvider->supportsClass(User::class));
        $this->assertFalse($this->userProvider->supportsClass(self::class));
    }
}
