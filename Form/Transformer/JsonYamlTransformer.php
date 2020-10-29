<?php /** @noinspection PhpMissingParamTypeInspection */

namespace Gupalo\GoogleAuthBundle\Form\Transformer;

use Symfony\Component\Form\DataTransformerInterface;
use Symfony\Component\Form\Exception\TransformationFailedException;
use Symfony\Component\Yaml\Yaml;

class JsonYamlTransformer implements DataTransformerInterface
{
    /**
     * @param array $value
     * @return string
     * @throws TransformationFailedException when the transformation fails
     */
    public function transform($value): string
    {
        return Yaml::dump($value);
    }

    /**
     * @param string $value
     * @return array
     * @throws TransformationFailedException when the transformation fails
     */
    public function reverseTransform($value): array
    {
        return Yaml::parse($value) ?? [];
    }
}
