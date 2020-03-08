<?php

namespace Gupalo\GoogleAuthBundle\DependencyInjection;

use Exception;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

class GoogleAuthExtension extends Extension implements PrependExtensionInterface
{
    public function prepend(ContainerBuilder $container): void
    {
        $config = [
            'clients' => [
                'google' => [
                    // must be "google" - it activates that type!
                    'type' => 'google',
                    // add and configure client_id and client_secret in services.yaml
                    'client_id' =>  $container->getParameter('google_auth_app_id'),
                    'client_secret' => $container->getParameter('google_auth_app_secret'),
                    // a route name you'll create
                    'redirect_route' => 'google_auth_connect_google_check',
                    'redirect_params' => [],
                    // Optional value for sending access_type parameter. More detail: https://developers.google.com/identity/protocols/OAuth2WebServer#offline
                    'access_type' => 'online',
                    // Optional value for sending hd parameter. More detail: https://developers.google.com/accounts/docs/OAuth2Login#hd-param
                    'hosted_domain' => $container->getParameter('google_auth_domain'),
                    // whether to check OAuth2 "state": defaults to true
                    'use_state' => false,
                ]
            ]
        ];
        $container->prependExtensionConfig('knpu_oauth2_client', $config);
    }

    /**
     * @param array $configs
     * @param ContainerBuilder $container
     * @throws Exception
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        $loader = new YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yaml');
    }
}
