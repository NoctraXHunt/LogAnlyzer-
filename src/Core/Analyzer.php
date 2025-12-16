<?php
namespace LogAnlyzer\Core;

use LogAnlyzer\Config;
use LogAnlyzer\Utils\LogParser;
use LogAnlyzer\Utils\Formatter;

class Analyzer
{
    private string $logFile;
    private array $ipCounter = [];
    private array $pathHits = [];
    private array $flags;

    public function __construct(string $logFile, array $flags = [])
    {
        $this->logFile = $logFile;
        $this->flags = $flags;
    }

    public function run(): void
    {
        $handle = fopen($this->logFile, 'r');
        if (!$handle) {
            echo Formatter::red("[!] Failed to open log file\n");
            return;
        }

        while (($line = fgets($handle)) !== false) {
            $data = LogParser::parseLine($line);
            if (!$data) continue;

            $ip = $data['ip'];
            $path = $data['path'];

            $this->ipCounter[$ip] = ($this->ipCounter[$ip] ?? 0) + 1;

            foreach (Config::SENSITIVE_PATHS as $sensitive) {
                if (str_starts_with($path, $sensitive)) {
                    $this->pathHits[$ip][] = $path;
                }
            }
        }

        fclose($handle);
        $this->report();
    }

    private function report(): void
    {
        arsort($this->ipCounter);

        $total = array_sum($this->ipCounter);
        $unique = count($this->ipCounter);

        echo Formatter::cyan("\n===== LogAnlyzer Report =====\n");
        echo Formatter::green("[+] Total Requests : {$total}\n");
        echo Formatter::green("[+] Unique IPs     : {$unique}\n\n");

        $suspicious = [];

        foreach ($this->ipCounter as $ip => $count) {
            if ($count >= Config::BRUTE_FORCE_THRESHOLD) {
                $suspicious[$ip] = [
                    'requests' => $count,
                    'sensitive_hits' => count($this->pathHits[$ip] ?? [])
                ];

                echo Formatter::red(
                    "- {$ip} → {$count} requests | Sensitive hits: " .
                    ($this->pathHits[$ip] ? count($this->pathHits[$ip]) : 0) . "\n"
                );
            }
        }

        if (empty($suspicious)) {
            echo Formatter::yellow("No suspicious activity detected.\n");
        }

        echo Formatter::cyan("============================\n");

        $this->export($total, $unique, $suspicious);
    }

    private function export(int $total, int $unique, array $suspicious): void
    {
        if (in_array('--json', $this->flags)) {
            if (!is_dir('output')) mkdir('output');
            file_put_contents(
                'output/report.json',
                json_encode(compact('total', 'unique', 'suspicious'), JSON_PRETTY_PRINT)
            );
            echo Formatter::green("[+] JSON report exported to output/report.json\n");
        }

        if (in_array('--csv', $this->flags)) {
            if (!is_dir('output')) mkdir('output');
            $fp = fopen('output/report.csv', 'w');
            fputcsv($fp, ['IP', 'Requests', 'SensitiveHits']);
            foreach ($suspicious as $ip => $data) {
                fputcsv($fp, [$ip, $data['requests'], $data['sensitive_hits']]);
            }
            fclose($fp);
            echo Formatter::green("[+] CSV report exported to output/report.csv\n");
        }
    }
}


