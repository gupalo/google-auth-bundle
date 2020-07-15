<?php

namespace Gupalo\GoogleAuthBundle\Tests\Entity;

use DateTime;
use Gupalo\GoogleAuthBundle\Entity\User;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Gupalo\GoogleAuthBundle\Entity\User
 */
class UserTest extends TestCase
{
    /** @var User */
    private $user;

    public function setUp(): void
    {
        $this->user = new class extends User {};
    }

    public function tearDown(): void
    {
        unset($this->user);
    }

    public function testId(): void
    {
        self::assertEquals(time(), $this->user->getCreatedAt()->getTimestamp(), 2);
        self::assertEquals(time(), $this->user->getLastActiveAt()->getTimestamp(), 2);
        self::assertNull($this->user->getId());
    }

    public function testCreatedAt(): void
    {
        self::assertEquals(time(), $this->user->getCreatedAt()->getTimestamp(), 2);
        $createdAt = new DateTime('-4 hours');
        $this->user->setCreatedAt($createdAt);
        self::assertSame($createdAt, $this->user->getCreatedAt());
    }

    public function testLastActiveAt(): void
    {
        self::assertEquals(time(), $this->user->getLastActiveAt()->getTimestamp(), 2);
        $lastActiveAt = new DateTime('-4 hours');
        $this->user->setLastActiveAt($lastActiveAt);
        self::assertSame($lastActiveAt, $this->user->getLastActiveAt());
    }

    public function testGoogleId(): void
    {
        self::assertSame('', $this->user->getGoogleId());
        $googleId = '123asd321';
        $this->user->setGoogleId($googleId);
        self::assertSame($googleId, $this->user->getGoogleId());
    }

    public function testGoogleAccessToken(): void
    {
        self::assertSame('', $this->user->getGoogleAccessToken());
        $googleAccessToken = '123asd321';
        $this->user->setGoogleAccessToken($googleAccessToken);
        self::assertSame($googleAccessToken, $this->user->getGoogleAccessToken());
    }

    public function testUsername(): void
    {
        self::assertSame('', $this->user->getUsername());
        $username = '123asd321';
        $this->user->setUsername($username);
        self::assertSame($username, $this->user->getUsername());
    }

    public function testEnabled(): void
    {
        self::assertFalse($this->user->getEnabled());
        $this->user->setEnabled(true);
        self::assertTrue($this->user->getEnabled());
    }

    public function testEmail(): void
    {
        self::assertSame('', $this->user->getEmail());
        $email = '123asd321';
        $this->user->setEmail($email);
        self::assertSame($email, $this->user->getEmail());
    }

    public function testGetRoles(): void
    {
        self::assertEquals([User::ROLE_USER], $this->user->getRoles());
    }

    public function testGetPassword(): void
    {
        self::assertNull($this->user->getPassword());
    }

    public function testGetSalt(): void
    {
        self::assertNull($this->user->getSalt());
    }

    public function testEraseCredentials(): void
    {
        self::assertNull($this->user->eraseCredentials());
    }
}
