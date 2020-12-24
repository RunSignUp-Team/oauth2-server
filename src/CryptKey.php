<?php
/**
 * Cryptography key holder.
 *
 * @author      Julián Gutiérrez <juliangut@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server;

use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Key\LocalFileReference;

use LogicException;
use RuntimeException;

class CryptKey
{
    const RSA_KEY_PATTERN =
        '/^(-----BEGIN (RSA )?(PUBLIC|PRIVATE) KEY-----)\R.*(-----END (RSA )?(PUBLIC|PRIVATE) KEY-----)\R?$/s';

    /**
     * @var Key
     */
    protected $key;

    /**
     * @var string
     */
    protected $keyPath;

    /**
     * @var null|string
     */
    protected $passPhrase;

    /**
     * @param string      $keyPath
     * @param null|string $passPhrase
     * @param bool        $keyPermissionsCheck
     */
    public function __construct($keyPath, $passPhrase = null, $keyPermissionsCheck = true)
    {
        if ($rsaMatch = \preg_match(static::RSA_KEY_PATTERN, $keyPath)) {
            $this->key = InMemory::plainText($keyPath);
        } elseif ($rsaMatch === false) {
            throw new \RuntimeException(
                \sprintf('PCRE error [%d] encountered during key match attempt', \preg_last_error())
            );
        }
        else
        {
            if (\strpos($keyPath, 'file://') !== 0) {
                $keyPath = 'file://' . $keyPath;
            }

            if (!\file_exists($keyPath) || !\is_readable($keyPath)) {
                throw new LogicException(\sprintf('Key path "%s" does not exist or is not readable', $keyPath));
            }

            if ($keyPermissionsCheck === true) {
                // Verify the permissions of the key
                $keyPathPerms = \decoct(\fileperms($keyPath) & 0777);
                if (\in_array($keyPathPerms, ['400', '440', '600', '640', '660'], true) === false) {
                    \trigger_error(\sprintf(
                        'Key file "%s" permissions are not correct, recommend changing to 600 or 660 instead of %s',
                        $keyPath,
                        $keyPathPerms
                    ), E_USER_NOTICE);
                }
            }

            $this->keyPath = $keyPath;
            $this->passPhrase = $passPhrase;
            $this->key = LocalFileReference::file($this->keyPath, $this->passPhrase ?? '');
        }
    }


    /**
     * Get key
     *
     * @return Key
     */
    public function getKey(): Key
    {
      return $this->key;
    }

    /**
     * Retrieve key path.
     *
     * @return string
     */
    public function getKeyPath()
    {
        return $this->keyPath;
    }

    /**
     * Retrieve key pass phrase.
     *
     * @return null|string
     */
    public function getPassPhrase()
    {
        return $this->passPhrase;
    }
}
