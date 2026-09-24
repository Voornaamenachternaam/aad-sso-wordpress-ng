<?php

declare(strict_types=1);

namespace PHPUnit\Framework;

if (!class_exists('PHPUnit\\Framework\\TestCase', false)) {
    class TestCase
    {
        private string $name;

        private ?string $expectedException = null;

        public function __construct(string $name = '')
        {
            $this->name = $name;
        }

        public static function setUpBeforeClass(): void {}

        public static function tearDownAfterClass(): void {}

        protected function setUp(): void {}

        protected function tearDown(): void {}

        public function expectException(string $exception): void
        {
            $this->expectedException = $exception;
        }

        public function expectExceptionMessage(string $message): void {}

        public function createMock(string $class): object
        {
            if (\Psr\Http\Message\ResponseInterface::class === $class) {
                return new class() implements \Psr\Http\Message\ResponseInterface {
                    private $body;

                    private $status = 200;

                    public function setBody($b): void
                    {
                        $this->body = $b;
                    }

                    public function setStatus($s): void
                    {
                        $this->status = $s;
                    }

                    public function getStatusCode(): int
                    {
                        return $this->status;
                    }

                    public function getBody(): \Psr\Http\Message\StreamInterface
                    {
                        return $this->body ?? \GuzzleHttp\Psr7\Utils::streamFor('');
                    }

                    public function getProtocolVersion(): string
                    {
                        return '1.1';
                    }

                    public function withProtocolVersion($version): static
                    {
                        return $this;
                    }

                    public function getHeaders(): array
                    {
                        return [];
                    }

                    public function hasHeader($name): bool
                    {
                        return false;
                    }

                    public function getHeader($name): array
                    {
                        return [];
                    }

                    public function getHeaderLine($name): string
                    {
                        return '';
                    }

                    public function withHeader($name, $value): static
                    {
                        return $this;
                    }

                    public function withAddedHeader($name, $value): static
                    {
                        return $this;
                    }

                    public function withoutHeader($name): static
                    {
                        return $this;
                    }

                    public function withBody(\Psr\Http\Message\StreamInterface $body): static
                    {
                        $this->body = $body;

                        return $this;
                    }

                    public function getReasonPhrase(): string
                    {
                        return '';
                    }

                    public function withStatus($code, $reasonPhrase = ''): static
                    {
                        $this->status = $code;

                        return $this;
                    }

                    public function method($m)
                    {
                        return new class($this, $m) {
                            private $resp;

                            private $m;

                            public function __construct($resp, $m)
                            {
                                $this->resp = $resp;
                                $this->m = $m;
                            }

                            public function willReturn($val): void
                            {
                                if ('getStatusCode' === $this->m) {
                                    $this->resp->setStatus($val);
                                }
                                if ('getBody' === $this->m) {
                                    $this->resp->setBody($val);
                                }
                            }
                        };
                    }
                };
            }
            if (\Psr\Http\Message\StreamInterface::class === $class) {
                return new class() implements \Psr\Http\Message\StreamInterface {
                    private $content = '';

                    public function setContent($c): void
                    {
                        $this->content = $c;
                    }

                    public function getContents(): string
                    {
                        return $this->content;
                    }

                    public function __toString(): string
                    {
                        return $this->content;
                    }

                    public function close(): void {}

                    public function detach()
                    {
                        return null;
                    }

                    public function getSize(): ?int
                    {
                        return mb_strlen($this->content);
                    }

                    public function tell(): int
                    {
                        return 0;
                    }

                    public function eof(): bool
                    {
                        return true;
                    }

                    public function isSeekable(): bool
                    {
                        return false;
                    }

                    public function seek($offset, $whence = \SEEK_SET): void {}

                    public function rewind(): void {}

                    public function isWritable(): bool
                    {
                        return false;
                    }

                    public function write($string): int
                    {
                        return 0;
                    }

                    public function isReadable(): bool
                    {
                        return true;
                    }

                    public function read($length): string
                    {
                        return $this->content;
                    }

                    public function getMetadata($key = null)
                    {
                        return null;
                    }

                    public function method($m)
                    {
                        return new class($this, $m) {
                            private $st;

                            private $m;

                            public function __construct($st, $m)
                            {
                                $this->st = $st;
                                $this->m = $m;
                            }

                            public function willReturn($val): void
                            {
                                if ('getContents' === $this->m) {
                                    $this->st->setContent($val);
                                }
                            }
                        };
                    }
                };
            }

            return new class($class) {
                private string $targetClass;

                private array $returnValues = [];

                public function __construct(string $targetClass)
                {
                    $this->targetClass = $targetClass;
                }

                public function method(string $method)
                {
                    $this->returnValues[$method] = null;

                    return new class($this, $method) {
                        private $mock;

                        private string $method;

                        public function __construct($mock, string $method)
                        {
                            $this->mock = $mock;
                            $this->method = $method;
                        }

                        public function willReturn($value): void
                        {
                            $this->mock->_setReturnValue($this->method, $value);
                        }
                    };
                }

                public function _setReturnValue(string $method, $value): void
                {
                    $this->returnValues[$method] = $value;
                }

                public function __call(string $method, array $args)
                {
                    if (\array_key_exists($method, $this->returnValues)) {
                        $val = $this->returnValues[$method];

                        return \is_callable($val) ? $val(...$args) : $val;
                    }

                    return null;
                }
            };
        }

        public static function assertTrue($cond, string $msg = ''): void
        {
            if (!$cond) {
                throw new \Exception('Failed asserting true. ' . $msg);
            }
        }

        public static function assertFalse($cond, string $msg = ''): void
        {
            if ($cond) {
                throw new \Exception('Failed asserting false. ' . $msg);
            }
        }

        public static function assertEquals($expected, $actual, string $msg = ''): void
        {
            if ($expected !== $actual) {
                throw new \Exception('Failed asserting ' . var_export($actual, true) . ' equals ' . var_export($expected, true) . '. ' . $msg);
            }
        }

        public static function assertSame($expected, $actual, string $msg = ''): void
        {
            if ($expected !== $actual) {
                throw new \Exception('Failed asserting ' . var_export($actual, true) . ' same ' . var_export($expected, true) . '. ' . $msg);
            }
        }

        public static function assertNotEquals($expected, $actual, string $msg = ''): void
        {
            if ($expected === $actual) {
                throw new \Exception('Failed asserting ' . var_export($actual, true) . ' not equals ' . var_export($expected, true) . '. ' . $msg);
            }
        }

        public static function assertIsArray($val, string $msg = ''): void
        {
            if (!\is_array($val)) {
                throw new \Exception('Failed asserting is array. ' . $msg);
            }
        }

        public static function assertIsObject($val, string $msg = ''): void
        {
            if (!\is_object($val)) {
                throw new \Exception('Failed asserting is object. ' . $msg);
            }
        }

        public static function assertContains($needle, $haystack, string $msg = ''): void
        {
            if (!\in_array($needle, (array) $haystack, true)) {
                throw new \Exception('Failed asserting contains. ' . $msg);
            }
        }

        public static function assertNotContains($needle, $haystack, string $msg = ''): void
        {
            if (\in_array($needle, (array) $haystack, true)) {
                throw new \Exception('Failed asserting not contains. ' . $msg);
            }
        }

        public static function assertCount($count, $haystack, string $msg = ''): void
        {
            if (\count((array) $haystack) !== $count) {
                throw new \Exception('Failed asserting count. ' . $msg);
            }
        }

        public static function assertInstanceOf(string $expected, $actual, string $msg = ''): void
        {
            if (!($actual instanceof $expected)) {
                throw new \Exception('Failed asserting instance of ' . $expected . '. ' . $msg);
            }
        }

        public static function assertNotNull($actual, string $msg = ''): void
        {
            if (null === $actual) {
                throw new \Exception('Failed asserting not null. ' . $msg);
            }
        }

        public static function assertNull($actual, string $msg = ''): void
        {
            if (null !== $actual) {
                throw new \Exception('Failed asserting null. ' . $msg);
            }
        }

        public static function assertStringContainsString(string $needle, string $haystack, string $msg = ''): void
        {
            if (!str_contains($haystack, $needle)) {
                throw new \Exception('Failed asserting string contains ' . $needle . '. ' . $msg);
            }
        }

        public static function assertStringNotContainsString(string $needle, string $haystack, string $msg = ''): void
        {
            if (str_contains($haystack, $needle)) {
                throw new \Exception('Failed asserting string not contains ' . $needle . '. ' . $msg);
            }
        }

        public static function assertLessThanOrEqual($expected, $actual, string $msg = ''): void
        {
            if ($actual > $expected) {
                throw new \Exception('Failed asserting less or equal. ' . $msg);
            }
        }

        public static function assertGreaterThanOrEqual($expected, $actual, string $msg = ''): void
        {
            if ($actual < $expected) {
                throw new \Exception('Failed asserting greater or equal. ' . $msg);
            }
        }

        public static function assertMatchesRegularExpression(string $pattern, string $string, string $msg = ''): void
        {
            if (!preg_match($pattern, $string)) {
                throw new \Exception('Failed asserting matches regex. ' . $msg);
            }
        }

        public static function assertArrayHasKey($key, array $array, string $msg = ''): void
        {
            if (!\array_key_exists($key, $array)) {
                throw new \Exception('Failed asserting array has key ' . $key . '. ' . $msg);
            }
        }

        public static function expectNotToPerformAssertions(): void {}

        public static function markTestSkipped(string $msg = ''): void
        {
            throw new SkippedTestError($msg);
        }

        public function getExpectedException(): ?string
        {
            return $this->expectedException;
        }
    }
    class SkippedTestError extends \Exception {}
}

namespace TestRunner;

require_once __DIR__ . '/bootstrap.php';

$test_files = glob(__DIR__ . '/Unit/*Test.php');
$total = 0;
$passed = 0;
$failed = 0;

foreach ($test_files as $file) {
    require_once $file;
    $class = 'AADSSO\\Tests\\Unit\\' . basename($file, '.php');
    if (!class_exists($class)) {
        continue;
    }

    $ref = new \ReflectionClass($class);
    if ($ref->hasMethod('setUpBeforeClass')) {
        $m = $ref->getMethod('setUpBeforeClass');
        $m->setAccessible(true);
        $m->invoke(null);
    }

    $methods = $ref->getMethods(\ReflectionMethod::IS_PUBLIC);

    foreach ($methods as $method) {
        if (!str_starts_with($method->getName(), 'test')) {
            continue;
        }

        ++$total;
        $instance = $ref->newInstance($method->getName());

        try {
            if ($ref->hasMethod('setUp')) {
                $setUp = $ref->getMethod('setUp');
                $setUp->setAccessible(true);
                $setUp->invoke($instance);
            }

            $method->invoke($instance);

            if (null !== $instance->getExpectedException()) {
                ++$failed;
                echo "FAIL: {$class}::{$method->getName()} - Expected exception {$instance->getExpectedException()} was not thrown.\n";
                continue;
            }

            if ($ref->hasMethod('tearDown')) {
                $tearDown = $ref->getMethod('tearDown');
                $tearDown->setAccessible(true);
                $tearDown->invoke($instance);
            }

            ++$passed;
            echo "PASS: {$class}::{$method->getName()}\n";
        } catch (\Throwable $e) {
            if ($e instanceof \PHPUnit\Framework\SkippedTestError) {
                echo "SKIP: {$class}::{$method->getName()} - " . $e->getMessage() . "\n";
                ++$passed;
                continue;
            }
            if (null !== $instance->getExpectedException() && $e instanceof ($instance->getExpectedException())) {
                ++$passed;
                echo "PASS (Expected Exception): {$class}::{$method->getName()}\n";
                continue;
            }

            ++$failed;
            echo "FAIL: {$class}::{$method->getName()} - " . $e->getMessage() . "\n";
            echo $e->getTraceAsString() . "\n";
        }
    }

    if ($ref->hasMethod('tearDownAfterClass')) {
        $m = $ref->getMethod('tearDownAfterClass');
        $m->setAccessible(true);
        $m->invoke(null);
    }
}

echo "\nTests run: {$total}, Passed: {$passed}, Failed: {$failed}\n";
if ($failed > 0) {
    exit(1);
}
