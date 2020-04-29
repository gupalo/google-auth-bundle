<?php

namespace Gupalo\GoogleAuthBundle\Tests\Security;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\Provider\GoogleClient;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GoogleUser;
use League\OAuth2\Client\Token\AccessToken;
use Gupalo\GoogleAuthBundle\Entity\User;
use Gupalo\GoogleAuthBundle\Model\UserManager;
use Gupalo\GoogleAuthBundle\Security\GoogleAuthenticator;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Prophecy\PhpUnit\ProphecyTrait;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class GoogleAuthenticatorTest extends TestCase
{
    use ProphecyTrait;

    /** @var GoogleAuthenticator */
    private $authenticator;

    /** @var ClientRegistry */
    private $clientRegistry;

    /** @var RouterInterface */
    private $router;

    private string $googleDomain = 'example.com';

    /** @var UserManager */
    private $userManager;

    protected function setUp(): void
    {
        $this->clientRegistry = $this->prophesize(ClientRegistry::class);
        $this->router = $this->prophesize(RouterInterface::class);
        $this->userManager = $this->prophesize(UserManager::class);

        $this->authenticator = new GoogleAuthenticator(
            $this->clientRegistry->reveal(),
            $this->router->reveal(),
            $this->userManager->reveal(),
            $this->googleDomain
        );
    }

    public function testGetCredentialsSkip(): void
    {
        $client = $this->prophesize(GoogleClient::class);

        $this->clientRegistry->getClient('google')->shouldBeCalledTimes(1)->willReturn($client->reveal());

        $request = Request::create('/some/path');
        $this->assertNull($this->authenticator->getCredentials($request));
    }

    public function testGetCredentials(): void
    {
        $request = Request::create('/some/path');
        $client = $this->prophesize(GoogleClient::class);
        $this->clientRegistry->getClient('google')->shouldBeCalledTimes(1)->willReturn($client->reveal());
        $token = 'some_token';
        $client->getAccessToken()->shouldBeCalledTimes(1)->willReturn($token);

        $result = $this->authenticator->getCredentials($request);

        $this->assertSame($token, $result);
    }

    public function testGetCredentialsException(): void
    {
        $this->expectException(IdentityProviderException::class);

        $request = Request::create('/some/path');
        $client = $this->prophesize(GoogleClient::class);
        $this->clientRegistry->getClient('google')->shouldBeCalledTimes(1)->willReturn($client->reveal());
        $client->getAccessToken()->shouldBeCalledTimes(1)->willThrow(new IdentityProviderException(1, 2, 3));

        $this->authenticator->getCredentials($request);
    }

    public function testGetUser_UserRegisteredViaGoogle(): void
    {
        $credentials = new AccessToken(['access_token' => 'token']);
        $googleClient = $this->prophesize(GoogleClient::class);
        $this->clientRegistry->getClient('google')->shouldBeCalledTimes(1)->willReturn($googleClient);
        $googleUser = new GoogleUser(['sub' => '123dsa213']);
        $googleClient->fetchUserFromToken($credentials)->shouldBeCalledTimes(1)->willReturn($googleUser);
        $user = (new User())->setUsername('user1');
        $this->userManager->findOneByGoogleId('123dsa213')->shouldBeCalledTimes(1)->willReturn($user);

        $result = $this->authenticator->getUser($credentials, $this->prophesize(UserProviderInterface::class)->reveal());

        $this->assertEquals($user, $result);
    }

    public function testGetUser_UserRegisteredViaGoogleNotAdminUser(): void
    {
        $credentials = new AccessToken(['access_token' => 'token']);
        $googleClient = $this->prophesize(GoogleClient::class);
        $this->clientRegistry->getClient('google')->shouldBeCalledTimes(1)->willReturn($googleClient);
        $googleUser = new GoogleUser(['sub' => '123dsa213']);
        $googleClient->fetchUserFromToken($credentials)->shouldBeCalledTimes(1)->willReturn($googleUser);
        $user = (new User())->setGoogleAccessToken('token')->setUsername('user1');
        $this->userManager->findOneByGoogleId('123dsa213')->shouldBeCalledTimes(1)->willReturn($user);

        $result = $this->authenticator->getUser($credentials, $this->prophesize(UserProviderInterface::class)->reveal());

        $this->assertEquals($user, $result);
        $this->assertEquals([User::ROLE_USER], $result->getRoles());
    }

    public function testGetUser_CreateNewUserInvalidEmilException(): void
    {
        $this->expectException(\Symfony\Component\Security\Core\Exception\AuthenticationException::class);

        $credentials = new AccessToken(['access_token' => 'token']);
        $googleClient = $this->prophesize(GoogleClient::class);
        $this->clientRegistry->getClient('google')->shouldBeCalledTimes(1)->willReturn($googleClient);
        $googleUser = new GoogleUser([
            'sub' => '123dsa213',
            'email' => 'email@test.com',
        ]);
        $googleClient->fetchUserFromToken($credentials)->shouldBeCalledTimes(1)->willReturn($googleUser);
        $this->userManager->findOneByGoogleId('123dsa213')->shouldBeCalledTimes(1)->willReturn(null);
        $this->userManager->findOneByEmail('email@test.com')->shouldBeCalledTimes(1)->willReturn(null);

        $result = $this->authenticator->getUser($credentials, $this->prophesize(UserProviderInterface::class)->reveal());

        $this->assertEquals('user', $result);
    }

    public function testGetUser_CreateNewUser(): void
    {
        $credentials = new AccessToken(['access_token' => 'token']);
        $googleClient = $this->prophesize(GoogleClient::class);
        $this->clientRegistry->getClient('google')->shouldBeCalledTimes(1)->willReturn($googleClient);
        $googleUser = new GoogleUser([
            'sub' => '123asd321',
            'email' => 'user1@example.com',
            'name' => 'Test Testerson',
            'given_name' => 'Test',
            'family_name' => 'Testerson',
            'picture' => 'http://example.com/1.jpg',
            'email_verified' => true,
            'locale' => 'en',
        ]);
        $googleClient->fetchUserFromToken($credentials)->shouldBeCalledTimes(1)->willReturn($googleUser);
        $this->userManager->findOneByGoogleId('123asd321')->shouldBeCalledTimes(1)->willReturn(null);
        $this->userManager->findOneByEmail('user1@example.com')->shouldBeCalledTimes(1)->willReturn(null);
        $user = new User();
        $this->userManager->createUser()->shouldBeCalledTimes(1)->willReturn($user);
        $user->setEnabled(true)->setEmail('user1@example.com')->setUsername('user1')->setGoogleId('123asd321');
        /** @noinspection PhpParamsInspection */
        $this->userManager->saveUser(Argument::that(function(User $user) {
            $this->assertFalse($user->getEnabled());
            $this->assertEquals('user1@example.com', $user->getEmail());
            $this->assertEquals('user1', $user->getUsername());
            $this->assertEquals('123asd321', $user->getGoogleId());
            $this->assertEquals(time(), $user->getCreatedAt()->getTimestamp(), 2);
            $this->assertEquals(time(), $user->getLastActiveAt()->getTimestamp(), 2);
            return true;
        }))->shouldBeCalledTimes(1);

        $userProvider = $this->prophesize(UserProviderInterface::class);
        $result = $this->authenticator->getUser($credentials, $userProvider->reveal());

        $this->assertEquals($user, $result);
    }

    public function testGetUser_RegisteredNotByGoogle_NotAdmin(): void
    {
        $credentials = new AccessToken(['access_token' => 'token']);
        $googleClient = $this->prophesize(GoogleClient::class);
        $this->clientRegistry->getClient('google')->shouldBeCalledTimes(1)->willReturn($googleClient);
        $googleUser = new GoogleUser([
            'sub' => '123dsa213',
            'email' => 'email@test.com',
            'name' => 'Test Testerson',
            'given_name' => 'Test',
            'family_name' => 'Testerson',
            'picture' => 'http://example.com/1.jpg',
            'email_verified' => true,
            'locale' => 'en',
        ]);
        $googleClient->fetchUserFromToken($credentials)->shouldBeCalledTimes(1)->willReturn($googleUser);
        $this->userManager->findOneByGoogleId('123dsa213')->shouldBeCalledTimes(1)->willReturn(null);
        $user = (new User())->setUsername('user2')->setCreatedAt(new \DateTime('2016-01-01'))->setLastActiveAt(new \DateTime('2016-10-10'));
        $this->userManager->findOneByEmail('email@test.com')->shouldBeCalledTimes(1)->willReturn($user);
        /** @noinspection PhpParamsInspection */
        $this->userManager->saveUser(Argument::that(function(User $arg) use ($user) {
            $this->assertEquals($arg, $user);
            return true;
        }))->shouldBeCalledTimes(1);

        $result = $this->authenticator->getUser($credentials, $this->prophesize(UserProviderInterface::class)->reveal());

        $this->assertEquals($user, $result);
        $this->assertEquals([User::ROLE_USER], $result->getRoles());
    }

    public function testCheckCredential(): void
    {
        $result =$this->authenticator->checkCredentials('credentials', $this->prophesize(UserInterface::class)->reveal());

        $this->assertTrue($result);
    }

    public function testOnAuthenticationFailure(): void
    {
        $request = new Request();
        $session = $this->prophesize(Session::class);
        $request->setSession($session->reveal());
        $session->set(Security::AUTHENTICATION_ERROR, new AuthenticationException())->shouldBeCalledTimes(1);
        $this->router->generate('google_auth_security_logout')->shouldBeCalledTimes(1)->willReturn('/login/url');

        $result = $this->authenticator->onAuthenticationFailure($request, new AuthenticationException());

        $this->assertInstanceOf(RedirectResponse::class, $result);
        $this->assertEquals('/login/url', $result->getTargetUrl());
    }

    public function testOnAuthenticationSuccess_NoPreviousUrl(): void
    {
        $providerKey = 'provider_key';
        $request = new Request();
        $session = $this->prophesize(Session::class);
        $request->setSession($session->reveal());
        $session->get('_security.'.$providerKey.'.target_path')->shouldBeCalledTimes(1)->willReturn(null);
        $this->router->generate('homepage')->shouldBeCalledTimes(1)->willReturn('/homepage');

        $result = $this->authenticator->onAuthenticationSuccess(
            $request,
            $this->prophesize(TokenInterface::class)->reveal(),
            $providerKey
        );

        $this->assertInstanceOf(RedirectResponse::class, $result);
        $this->assertEquals('/homepage', $result->getTargetUrl());
    }

    public function testOnAuthenticationSuccess_WithPreviousUrl(): void
    {
        $providerKey = 'provider_key';
        $request = new Request();
        $session = $this->prophesize(Session::class);
        $request->setSession($session->reveal());
        $session->get('_security.'.$providerKey.'.target_path')->shouldBeCalledTimes(1)->willReturn('/prev/page');

        $result = $this->authenticator->onAuthenticationSuccess(
            $request,
            $this->prophesize(TokenInterface::class)->reveal(),
            $providerKey
        );

        $this->assertInstanceOf(RedirectResponse::class, $result);
        $this->assertEquals('/prev/page', $result->getTargetUrl());
    }

    public function testStart(): void
    {
        $request = new Request();
        $this->router->generate('google_auth_security_login')->shouldBeCalledTimes(1)->willReturn('/homepage');

        $result = $this->authenticator->start($request);

        $this->assertInstanceOf(RedirectResponse::class, $result);
        $this->assertEquals('/homepage', $result->getTargetUrl());
    }
}
