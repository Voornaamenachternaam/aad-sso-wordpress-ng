<?php

namespace AADSSO\Firebase\JWT;

use UnexpectedValueException;

/**
 * Exception thrown when the token has expired (exp claim).
 */
class ExpiredException extends UnexpectedValueException
{

}
