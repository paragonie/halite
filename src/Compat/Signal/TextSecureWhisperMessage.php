<?php
namespace ParagonIE\Halite\Compat\Signal;

/**
 * This is what gets serialized (protobuf-style) and sent to the client.
 */
class TextSecureWhisperMessage
{
    protected $version;
    protected $whisperMessage;
    protected $mac;
}
