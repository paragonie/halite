<?php
namespace ParagonIE\Halite\Contract;

/**
 * An interface for database interaction.
 */
interface DBInterface
{
    /**
     * Variadic version of $this->column()
     *
     * @param string $statement SQL query without user data
     * @param int $offset - How many columns from the left are we grabbing from each row?
     * @params ... $params Parameters
     * @return mixed
     */
    public function col($statement, $offset = 0, ...$params);
    
    /**
     * Fetch a column
     *
     * @param string $statement SQL query without user data
     * @param int $offset - How many columns from the left are we grabbing from each row?
     * @params ... $params Parameters
     * @return mixed
     */
    public function column($statement, $params = [], $offset = 0);
    
    /**
     * Variadic version of $this->single()
     *
     * @param string $statement SQL query without user data
     * @params mixed ...$params Parameters
     * @return mixed
     */
    public function cell($statement, ...$params);
    
    /**
     * Delete rows in a database table.
     *
     * @param string $table - table name
     * @param array $conditions - WHERE clause
     */
    public function delete($table, array $conditions);
    
    /**
     * Insert a new row to a table in a database.
     *
     * @param string $table - table name
     * @param array $map - associative array of which values should be assigned to each field
     */
    public function insert($table, array $map);
    
    /**
     * Similar to $this->run() except it only returns a single row
     *
     * @param string $statement SQL query without user data
     * @params mixed ...$params Parameters
     */
    public function row($statement, ...$params);
    
    /**
     * Run a query, get a 2D array with all the results
     *
     * @param string $statement SQL query without user data
     * @params mixed ...$params Parameters
     * @return mixed - If successful, a 2D array
     */
    public function run($statement, ...$params);
    
    /**
     * Fetch a single result -- useful for SELECT COUNT() queries
     *
     * @param string $statement
     * @param array $params
     * @return mixed
     */
    public function single($statement, $params = []);
    
    /**
     * Update a row in a database table.
     *
     * @param string $table - table name
     * @param array $changes - associative array of which values should be assigned to each field
     * @param array $conditions - WHERE clause
     */
    public function update($table, array $changes, array $conditions);
}
