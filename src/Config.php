<?php
namespace LogAnlyzer;

/**
 * Global configuration for LogAnlyzer
 * Adjust values here to fit your environment
 */
class Config
{
    /**
     * Number of requests from a single IP
     * to be considered suspicious
     */
    public const BRUTE_FORCE_THRESHOLD = 500;

    /**
     * Sensitive paths often targeted by attackers
     * Used for pattern-based detection
     */
    public const SENSITIVE_PATHS = [
        '/login',
        '/admin',
        '/wp-login',
        '/auth',
        '/signin',
        '/dashboard'
    ];

    /**
     * Maximum number of sensitive path hits
     * before marking an IP as suspicious
     */
    public const SENSITIVE_HIT_THRESHOLD = 20;

    /**
     * Enable or disable colored CLI output
     */
    public const ENABLE_COLORS = true;
}
