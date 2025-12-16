<?php
namespace LogAnlyzer\Utils;

class LogParser
{
    /**
     * Parse one line of access log
     * Supports common Apache / Nginx log format
     */
    public static function parseLine(string $line): ?array
    {
        /*
         Example log:
         192.168.1.10 - - [16/Dec/2025:10:12:33 +0700] "POST /login HTTP/1.1" 200 532
        */

        $pattern = '/^(\S+) .*? .*? "(GET|POST|PUT|DELETE|HEAD|OPTIONS) (\S+)/';

        if (!preg_match($pattern, $line, $matches)) {
            return null;
        }

        return [
            'ip'     => $matches[1],
            'method' => $matches[2],
            'path'   => $matches[3],
        ];
    }
}
