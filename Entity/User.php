<?php

namespace Gupalo\GoogleAuthBundle\Entity;

use DateTime;
use DateTimeInterface;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * User class with minimum needed fields
 *
 * @ORM\Entity()
 * @ORM\Table(name="user")
 */
class User implements UserInterface
{
    public const ROLE_GUEST = 'ROLE_GUEST';
    public const ROLE_USER = 'ROLE_USER';
    public const ROLE_API = 'ROLE_API';
    public const ROLE_MANAGER = 'ROLE_MANAGER';
    public const ROLE_ADMIN = 'ROLE_ADMIN';

    /**
     * @ORM\Id()
     * @ORM\GeneratedValue()
     * @ORM\Column(type="integer", name="id")
     */
    protected ?int $id = null;

    /**
     * @ORM\Column(type="datetime", name="created_at")
     */
    protected DateTimeInterface $createdAt;

    /**
     * @ORM\Column(type="datetime", nullable=true, name="last_active_at")
     */
    protected ?DateTimeInterface $lastActiveAt = null;

    /**
     * @ORM\Column(type="boolean", nullable=true, name="is_enabled")
     */
    protected ?bool $enabled = false;

    /**
     * @ORM\Column(type="string", length=255, nullable=true, name="username")
     */
    protected ?string $username = null;

    /**
     * @ORM\Column(type="string", length=255, nullable=true, name="email")
     */
    protected ?string $email = null;

    /**
     * @ORM\Column(type="string", length=255, nullable=true, name="google_id")
     */
    protected ?string $googleId = null;

    /**
     * @ORM\Column(type="string", length=255, nullable=true, name="google_access_token")
     */
    protected ?string $googleAccessToken = null;

    /**
     * @ORM\Column(type="string", length=255, nullable=true, name="api_key")
     */
    protected ?string $apiKey = null;

    /**
     * @ORM\Column(type="string", length=1024, nullable=true, name="roles")
     */
    protected ?string $roles = self::ROLE_USER;

    /**
     * @ORM\Column(type="string", length=255, nullable=true, name="name")
     */
    protected ?string $name = null;

    /**
     * @ORM\Column(type="string", length=255, nullable=true, name="first_name")
     */
    protected ?string $firstName = null;

    /**
     * @ORM\Column(type="string", length=255, nullable=true, name="surname")
     */
    protected ?string $surname = null;

    /**
     * @ORM\Column(type="string", length=1024, nullable=true, name="picture_url")
     */
    protected ?string $pictureUrl = null;

    /**
     * @ORM\Column(type="boolean", nullable=true, name="is_email_verified")
     */
    protected ?bool $isEmailVerified = null;

    /**
     * @ORM\Column(type="string", length=255, nullable=true, name="locale")
     */
    protected ?string $locale;

    protected bool $isApiAuth = false;

    /**
     * @ORM\Column(type="json", length=1000000, nullable=true, name="data")
     */
    protected ?array $data = [];

    public function __construct(int $id = null)
    {
        $this->createdAt = new DateTime();
        $this->lastActiveAt = new DateTime();

        if ($id) {
            $this->id = $id;
        }
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function setCreatedAt(DateTime $createdAt): self
    {
        $this->createdAt = $createdAt;

        return $this;
    }

    public function getCreatedAt(): ?DateTime
    {
        return $this->createdAt;
    }

    public function setLastActiveAt(DateTime $lastActiveAt): self
    {
        $this->lastActiveAt = $lastActiveAt;

        return $this;
    }

    public function getLastActiveAt(): ?DateTime
    {
        return $this->lastActiveAt;
    }

    public function setGoogleId(string $googleId): self
    {
        $this->googleId = $googleId;

        return $this;
    }

    public function getGoogleId(): ?string
    {
        return $this->googleId;
    }

    public function setGoogleAccessToken(string $googleAccessToken): self
    {
        $this->googleAccessToken = $googleAccessToken;

        return $this;
    }

    public function getGoogleAccessToken(): ?string
    {
        return $this->googleAccessToken;
    }

    /**
     * Returns the roles granted to the user.
     *
     * <code>
     * public function getRoles()
     * {
     *     return array('ROLE_USER');
     * }
     * </code>
     *
     * Alternatively, the roles might be stored on a ``roles`` property,
     * and populated in any number of different ways when the user object
     * is created.
     *
     * @return string[] The user roles
     */
    public function getRoles(): array
    {
        if (empty($this->roles)) {
            $this->setRoles([self::ROLE_USER]);
        }

        return explode(',', $this->roles);
    }

    public function setRoles(array $roles): self
    {
        if (empty($roles)) {
            $roles = [self::ROLE_USER];
        }

        $this->roles = implode(',', $roles);

        return $this;
    }

    /**
     * Returns the password used to authenticate the user.
     *
     * This should be the encoded password. On authentication, a plain-text
     * password will be salted, encoded, and then compared to this value.
     *
     * @return string The password
     */
    public function getPassword(): ?string
    {
        return null;
    }

    /**
     * Returns the salt that was originally used to encode the password.
     *
     * This can return null if the password was not encoded using a salt.
     *
     * @return string|null The salt
     */
    public function getSalt(): ?string
    {
        return null;
    }

    /**
     * Returns the username used to authenticate the user.
     *
     * @return string The username
     */
    public function getUsername(): ?string
    {
        return $this->username;
    }

    /**
     * Removes sensitive data from the user.
     *
     * This is important if, at any given point, sensitive information like
     * the plain-text password is stored on this object.
     */
    public function eraseCredentials(): void
    {
        return;
    }

    public function setEnabled(bool $enabled): self
    {
        $this->enabled = $enabled;

        return $this;
    }

    public function getEnabled(): ?bool
    {
        return $this->enabled;
    }

    public function setUsername(string $username): self
    {
        $this->username = $username;

        return $this;
    }

    public function setEmail(string $email): self
    {
        $this->email = $email;

        return $this;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function getApiKey(): string
    {
        return $this->apiKey;
    }

    public function setApiKey(string $apiKey): self
    {
        $this->apiKey = $apiKey;

        return $this;
    }

    public function getData(): array
    {
        return $this->data ?? [];
    }

    public function setData(array $data): self
    {
        $this->data = $data;

        return $this;
    }

    public function isApiAuth(): bool
    {
        return $this->isApiAuth;
    }

    public function setIsApiAuth(bool $isApiAuth): self
    {
        $this->isApiAuth = $isApiAuth;

        return $this;
    }

    public function getName(): ?string
    {
        return $this->name;
    }

    public function setName(string $name): self
    {
        $this->name = $name;

        return $this;
    }

    public function getFirstName(): ?string
    {
        return $this->firstName;
    }

    public function setFirstName(string $firstName): self
    {
        $this->firstName = $firstName;

        return $this;
    }

    public function getSurname(): ?string
    {
        return $this->surname;
    }

    public function setSurname(string $surname): self
    {
        $this->surname = $surname;

        return $this;
    }

    public function getPictureUrl(): ?string
    {
        return $this->pictureUrl;
    }

    public function setPictureUrl(string $pictureUrl): self
    {
        $this->pictureUrl = $pictureUrl;

        return $this;
    }

    public function isEmailVerified(): ?bool
    {
        return $this->isEmailVerified;
    }

    public function setIsEmailVerified(bool $isEmailVerified): self
    {
        $this->isEmailVerified = $isEmailVerified;

        return $this;
    }

    public function getLocale(): ?string
    {
        return $this->locale;
    }

    public function setLocale(string $locale): self
    {
        $this->locale = $locale;

        return $this;
    }

    public function __toString(): string
    {
        return $this->username ?? (string)$this->id;
    }
}
