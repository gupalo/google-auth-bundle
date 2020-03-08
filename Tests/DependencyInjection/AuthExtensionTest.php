<?php

namespace Gupalo\GoogleAuthBundle\Tests\DependencyInjection;

use Gupalo\GoogleAuthBundle\DependencyInjection\GoogleAuthExtension;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * @covers \Gupalo\GoogleAuthBundle\DependencyInjection\GoogleAuthExtension
 */
class AuthExtensionTest extends TestCase
{
    public function testPrepend(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('google_auth_app_id', '123asd321');
        $container->setParameter('google_auth_app_secret', 'asd123dsa');
        $container->setParameter('google_auth_domain', 'example.com');
        $loader = new GoogleAuthExtension();
        $loader->prepend($container);
        $expected = [
            'clients' => [
                'google' => [
                    'type' => 'google',
                    'client_id' =>  '123asd321',
                    'client_secret' => 'asd123dsa',
                    'redirect_route' => 'google_auth_connect_google_check',
                    'redirect_params' => [],
                    'access_type' => 'online',
                    'hosted_domain' => 'example.com',
                    'use_state' => false
                ]
            ]
        ];
        $this->assertEquals([0 => $expected], $container->getExtensionConfig('knpu_oauth2_client'));
    }

    public function testLoad(): void
    {
        $container = new ContainerBuilder();
        $loader = new GoogleAuthExtension();
        $config = [];
        $loader->load([$config], $container);

        $expectedServices = [
            'service_container',
            'google_auth.controller.api',
            'google_auth.controller.google',
            'google_auth.model.user_manager',
            'google_auth.security.google_authenticator',
            'google_auth.security.api_key_user_provider',
            'google_auth.security.api_key_authenticator',
            'twig.security_extension',
        ];
        $this->assertEquals($expectedServices, array_keys($container->getDefinitions()));
    }
}
