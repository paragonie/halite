<?php
namespace ParagonIE\Halite\Contract;

/**
 * An interface for database interaction.
 */
interface RouterInterface
{
    /**
     * You should be able to pass cabin configurations here
     * 
     * @param array $cabins
     */
    public function __construct(array $cabins = []);
    
    /**
     * 
     */
    public function route();
}