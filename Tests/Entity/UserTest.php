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
        $this->assertEquals(time(), $this->user->getCreatedAt()->getTimestamp(), 2);
        $this->assertEquals(time(), $this->user->getLastActiveAt()->getTimestamp(), 2);
        $this->assertNull($this->user->getId());
    }

    public function testCreatedAt(): void
    {
        $this->assertEquals(time(), $this->user->getCreatedAt()->getTimestamp(), 2);
        $createdAt = new DateTime('-4 hours');
        $this->user->setCreatedAt($createdAt);
        $this->assertSame($createdAt, $this->user->getCreatedAt());
    }

    public function testLastActiveAt(): void
    {
        $this->assertEquals(time(), $this->user->getLastActiveAt()->getTimestamp(), 2);
        $lastActiveAt = new DateTime('-4 hours');
        $this->user->setLastActiveAt($lastActiveAt);
        $this->assertSame($lastActiveAt, $this->user->getLastActiveAt());
    }

    public function testGoogleId(): void
    {
        $this->assertNull($this->user->getGoogleId());
        $googleId = '123asd321';
        $this->user->setGoogleId($googleId);
        $this->assertSame($googleId, $this->user->getGoogleId());
    }

    public function testGoogleAccessToken(): void
    {
        $this->assertNull($this->user->getGoogleAccessToken());
        $googleAccessToken = '123asd321';
        $this->user->setGoogleAccessToken($googleAccessToken);
        $this->assertSame($googleAccessToken, $this->user->getGoogleAccessToken());
    }

    public function testUsername(): void
    {
        $this->assertNull($this->user->getUsername());
        $username = '123asd321';
        $this->user->setUsername($username);
        $this->assertSame($username, $this->user->getUsername());
    }

    public function testEnabled(): void
    {
        $this->assertFalse($this->user->getEnabled());
        $this->user->setEnabled(true);
        $this->assertTrue($this->user->getEnabled());
    }

    public function testEmail(): void
    {
        $this->assertNull($this->user->getEmail());
        $email = '123asd321';
        $this->user->setEmail($email);
        $this->assertSame($email, $this->user->getEmail());
    }

    public function testGetRoles(): void
    {
        $this->assertEquals([User::ROLE_USER], $this->user->getRoles());
    }

    public function testGetPassword(): void
    {
        $this->assertNull($this->user->getPassword());
    }

    public function testGetSalt(): void
    {
        $this->assertNull($this->user->getSalt());
    }

    public function testEraseCredentials(): void
    {
        $this->assertNull($this->user->eraseCredentials());
    }
}
