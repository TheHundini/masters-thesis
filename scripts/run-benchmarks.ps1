param(
    [ValidateSet("all", "signatures", "keygen", "lifecycle", "tls")]
    [string]$Suite = "all",

    [ValidateSet("default", "thesis")]
    [string]$Preset = "default",

    [ValidateSet("none", "gc", "stack", "comp", "mempool", "pauses", "safepoints", "jfr")]
    [string]$Profiler = "gc",

    [switch]$Jfr,

    [switch]$SkipSummary,

    [string]$ResultDir = "benchmark-results",

    [switch]$Representative1024,

    [int]$WarmupIterations = -1,

    [int]$MeasurementIterations = -1,

    [int]$Forks = -1,

    [int]$IterationSeconds = -1
)

$ErrorActionPreference = "Stop"

$classpathFile = Join-Path "target" "benchmark-classpath.txt"

function Assert-Success {
    param([string]$Step)

    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE"
    }
}

function Resolve-JfrTool {
    $command = Get-Command "jfr" -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $java = Get-Command "java" -ErrorAction SilentlyContinue
    if ($java) {
        $candidate = Join-Path (Split-Path $java.Source -Parent) "jfr.exe"
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    return $null
}

function Invoke-JfrPostProcessing {
    param(
        [string]$Directory,
        [datetime]$StartedAt
    )

    $jfrTool = Resolve-JfrTool
    if (-not $jfrTool) {
        Write-Warning "JFR recordings were requested, but the 'jfr' tool was not found on PATH or beside java."
        return
    }

    $recordings = @(Get-ChildItem -Path $Directory -Filter "*.jfr" -File -Recurse |
        Where-Object { $_.LastWriteTime -ge $StartedAt })

    if ($recordings.Count -eq 0) {
        Write-Warning "No JFR recordings were found in $Directory."
        return
    }

    foreach ($recording in $recordings) {
        $base = Join-Path $recording.DirectoryName $recording.BaseName

        & $jfrTool summary $recording.FullName |
            Set-Content -Path "$base-jfr-summary.txt" -Encoding utf8
        & $jfrTool view --width 160 hot-methods $recording.FullName |
            Set-Content -Path "$base-jfr-hot-methods.txt" -Encoding utf8
        & $jfrTool view --width 160 allocation-by-class $recording.FullName |
            Set-Content -Path "$base-jfr-allocation-by-class.txt" -Encoding utf8
        & $jfrTool view --width 160 gc $recording.FullName |
            Set-Content -Path "$base-jfr-gc.txt" -Encoding utf8
    }

    Write-Host "JFR post-processing wrote summary, hot-method, allocation, and GC text files for $($recordings.Count) recording(s)."
}

Write-Host "Compiling benchmarks..."
mvn -q -DskipTests clean compile
Assert-Success "Compiling benchmarks"

New-Item -ItemType Directory -Force -Path $ResultDir | Out-Null
$resultDirPath = (Resolve-Path $ResultDir).Path

$include = switch ($Suite) {
    "keygen" { "SignatureKeyGenerationBenchmark" }
    "lifecycle" { "SignatureFullLifecycleBenchmark" }
    "signatures" { "SignatureServiceBenchmark" }
    "tls" { "TlsHandshakeBenchmark" }
    default { ".*Benchmark" }
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$baseName = "$Suite-$timestamp"
$resultFile = Join-Path $resultDirPath "$baseName.json"
$jfrRequested = $Jfr -or $Profiler -eq "jfr"

if ($Preset -eq "thesis") {
    $Representative1024 = $true

    if ($WarmupIterations -lt 0) {
        $WarmupIterations = 1
    }
    if ($MeasurementIterations -lt 0) {
        $MeasurementIterations = 3
    }
    if ($Forks -lt 0) {
        $Forks = 1
    }
    if ($IterationSeconds -lt 0) {
        $IterationSeconds = 1
    }
}

if ($jfrRequested) {
    $jfrTempDir = Join-Path $resultDirPath "$baseName-jfr-tmp"
    New-Item -ItemType Directory -Force -Path $jfrTempDir | Out-Null
}

Write-Host "Running JMH suite '$Suite'..."
Write-Host "Building classpath for benchmark dependencies..."
mvn -q "-DincludeScope=runtime" "-Dmdep.outputFile=$classpathFile" dependency:build-classpath
Assert-Success "Building benchmark classpath"

$dependencyClasspath = Get-Content $classpathFile
$benchmarkClasspath = "target/classes;$dependencyClasspath"

$classpathArgs = @(
    "-cp", $benchmarkClasspath,
    "org.openjdk.jmh.Main",
    $include,
    "-rf", "json",
    "-rff", $resultFile
)

if ($Profiler -ne "none") {
    if ($Profiler -eq "jfr") {
        $classpathArgs += @("-prof", "jfr:dir=$resultDirPath;configName=profile")
    } else {
        $classpathArgs += @("-prof", $Profiler)
    }
}

if ($Jfr -and $Profiler -ne "jfr") {
    $classpathArgs += @("-prof", "jfr:dir=$resultDirPath;configName=profile")
}

if ($Representative1024) {
    $classpathArgs += @("-p", "payloadSizeBytes=1024", "-p", "messageSizeBytes=1024")
}

if ($WarmupIterations -ge 0) {
    $classpathArgs += @("-wi", "$WarmupIterations")
}

if ($MeasurementIterations -ge 0) {
    $classpathArgs += @("-i", "$MeasurementIterations")
}

if ($Forks -ge 0) {
    $classpathArgs += @("-f", "$Forks")
}

if ($IterationSeconds -gt 0) {
    $classpathArgs += @("-w", "${IterationSeconds}s", "-r", "${IterationSeconds}s")
}

if ($jfrRequested) {
    $classpathArgs += @("-jvmArgsAppend", "-Djava.io.tmpdir=$jfrTempDir")
}

$runStarted = Get-Date
& java @classpathArgs
Assert-Success "Running JMH"

if ($jfrRequested) {
    Invoke-JfrPostProcessing $resultDirPath $runStarted
}

if (-not $SkipSummary) {
    Write-Host "Summarizing JMH JSON into CSV and Markdown..."
    $summaryScript = Join-Path $PSScriptRoot "summarize-benchmarks.ps1"
    & $summaryScript -InputPath $resultFile
    Assert-Success "Summarizing benchmarks"
}
