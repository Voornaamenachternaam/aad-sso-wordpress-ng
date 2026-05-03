<?php

namespace AADSSO\Firebase\JWT;

use UnexpectedValueException;

/**
 * Exception thrown when the token is being used before it's valid (nbf claim).
 */
class BeforeValidException extends UnexpectedValueException
{

}
