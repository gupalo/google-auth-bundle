<?php

namespace Gupalo\GoogleAuthBundle\Form;

use Gupalo\GoogleAuthBundle\Entity\User;
use Gupalo\GoogleAuthBundle\Form\Transformer\JsonYamlTransformer;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\CheckboxType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\Extension\Core\Type\TextareaType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class UserType extends AbstractType
{
    private JsonYamlTransformer $jsonYamlTransformer;

    public function __construct(JsonYamlTransformer $jsonYamlTransformer)
    {
        $this->jsonYamlTransformer = $jsonYamlTransformer;
    }

    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('enabled', CheckboxType::class, [
                'label' => 'is enabled',
                'required' => false,
            ])
            ->add('username', TextType::class, [
                'label' => 'Username',
            ])
            ->add('apiKey', TextType::class, [
                'label' => 'API Key',
                'required' => false,
            ])
            ->add('roles', TextareaType::class, [
                'label' => 'Roles',
                'help' => 'YAML-format. Array of "ROLE_*"',
                'attr' => [
                    'rows' => 5,
                    'style' => 'font-family: Consolas, "Courier New", monospaced; font-size: 13px',
                    'wrap' => 'off',
                ],
            ])
            ->add('data', TextareaType::class, [
                'label' => 'Data',
                'help' => 'YAML-format',
                'attr' => [
                    'rows' => 5,
                    'style' => 'font-family: Consolas, "Courier New", monospaced; font-size: 13px',
                    'wrap' => 'off',
                ],
            ])
            ->add('save', SubmitType::class, ['label' => 'Save']);

        $builder->get('roles')->addModelTransformer($this->jsonYamlTransformer);
        $builder->get('data')->addModelTransformer($this->jsonYamlTransformer);
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => User::class,
        ]);
    }
}
