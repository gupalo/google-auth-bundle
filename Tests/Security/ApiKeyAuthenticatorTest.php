<?php

namespace Gupalo\GoogleAuthBundle\Tests\Security;

use Gupalo\GoogleAuthBundle\Entity\User;
use Gupalo\GoogleAuthBundle\Security\ApiKeyAuthenticator;
use Gupalo\GoogleAuthBundle\Security\ApiKeyUserProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\ParameterBag;
use Symfony\Component\HttpFoundation\Request;

class ApiKeyAuthenticatorTest extends TestCase
{
    /** @var string */
    private $apiKey;

    /** @var string */
    private $username;

    /** @var User */
    private $user;

    /** @var Request */
    private $request;

    /** @var ParameterBag */
    private $requestHeaders;

    /** @var ParameterBag */
    private $requestRequest;

    /** @var ParameterBag */
    private $requestQuery;

    /** @var ApiKeyUserProvider */
    private $userProvider;

    protected function setUp(): void
    {
        $this->apiKey = 'SuperKey';
        $this->username = 'user1';
        $this->user = (new User())->setUsername($this->username);

        $this->request = $this->prophesize(Request::class);
        $this->userProvider = $this->prophesize(ApiKeyUserProvider::class);

        $this->requestHeaders = $this->prophesize(ParameterBag::class);
        $this->requestRequest = $this->prophesize(ParameterBag::class);
        $this->requestQuery = $this->prophesize(ParameterBag::class);

        $this->request->headers = $this->requestHeaders;
        $this->request->request = $this->requestRequest;
        $this->request->query = $this->requestQuery;
    }

    public function testGetUser_Header(): void
    {
        $this->requestHeaders->get('X-Api-Key')->shouldBeCalledTimes(1)->willReturn($this->apiKey);
        $this->userProvider->loadUserByApiKey($this->apiKey)->shouldBeCalledTimes(1)->willReturn($this->user);

        $authenticator = new ApiKeyAuthenticator();
        $credentials = $authenticator->getCredentials($this->request->reveal());
        $this->assertSame(['token' => $this->apiKey], $credentials);

        $user = $authenticator->getUser($credentials, $this->userProvider->reveal());
        $this->assertSame($user, $this->user);
    }

    public function testGetUser_Request(): void
    {
        $this->requestHeaders->get('X-Api-Key')->shouldBeCalledTimes(1)->willReturn(null);
        $this->requestRequest->get('apikey')->shouldBeCalledTimes(1)->willReturn($this->apiKey);
        $this->userProvider->loadUserByApiKey($this->apiKey)->shouldBeCalledTimes(1)->willReturn($this->user);

        $authenticator = new ApiKeyAuthenticator();
        $credentials = $authenticator->getCredentials($this->request->reveal());
        $this->assertSame(['token' => $this->apiKey], $credentials);

        $user = $authenticator->getUser($credentials, $this->userProvider->reveal());
        $this->assertSame($user, $this->user);
    }

    public function testGetUser_Query(): void
    {
        $this->requestHeaders->get('X-Api-Key')->shouldBeCalledTimes(1)->willReturn(null);
        $this->requestRequest->get('apikey')->shouldBeCalledTimes(1)->willReturn(null);
        $this->requestQuery->get('apikey')->shouldBeCalledTimes(1)->willReturn($this->apiKey);
        $this->userProvider->loadUserByApiKey($this->apiKey)->shouldBeCalledTimes(1)->willReturn($this->user);

        $authenticator = new ApiKeyAuthenticator();
        $credentials = $authenticator->getCredentials($this->request->reveal());
        $this->assertSame(['token' => $this->apiKey], $credentials);

        $user = $authenticator->getUser($credentials, $this->userProvider->reveal());
        $this->assertSame($user, $this->user);
    }

    public function testGetUser_IncorrectApiKey(): void
    {
        $this->requestHeaders->get('X-Api-Key')->shouldBeCalledTimes(1)->willReturn('BAD');
        $this->userProvider->loadUserByApiKey('BAD')->shouldBeCalledTimes(1)->willReturn(null);

        $authenticator = new ApiKeyAuthenticator();
        $credentials = $authenticator->getCredentials($this->request->reveal());

        $user = $authenticator->getUser($credentials, $this->userProvider->reveal());
        $this->assertNull($user);
    }
}
