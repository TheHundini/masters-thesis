param(
    [string]$InputPath,

    [string]$OutputDir,

    [switch]$SkipSizeMetadata
)

$ErrorActionPreference = "Stop"

function Resolve-InputPath {
    param([string]$Path)

    if ($Path) {
        return (Resolve-Path $Path).Path
    }

    $latest = Get-ChildItem -Path "benchmark-results" -Filter "*.json" -File |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($null -eq $latest) {
        throw "No benchmark JSON files found in benchmark-results."
    }

    return $latest.FullName
}

function Get-ObjectValue {
    param(
        [object]$Object,
        [string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Get-ParamValue {
    param(
        [object]$Result,
        [string]$Name
    )

    return Get-ObjectValue $Result.params $Name
}

function Get-MetricValue {
    param(
        [object]$Result,
        [string]$MetricName,
        [string]$Field = "score"
    )

    $metric = Get-ObjectValue $Result.secondaryMetrics $MetricName
    return Get-ObjectValue $metric $Field
}

function Get-PrimaryPercentile {
    param(
        [object]$Result,
        [string]$Percentile
    )

    return Get-ObjectValue $Result.primaryMetric.scorePercentiles $Percentile
}

function Assert-CommandSuccess {
    param([string]$Step)

    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE"
    }
}

function Invoke-SizeMetadataExport {
    param(
        [string]$SignatureMetadataPath,
        [string]$TlsMetadataPath
    )

    Write-Host "Collecting signature and TLS size metadata..."

    mvn -q -DskipTests compile
    Assert-CommandSuccess "Compiling metadata exporter"

    $classpathFile = Join-Path "target" "benchmark-classpath.txt"

    mvn -q "-DincludeScope=runtime" "-Dmdep.outputFile=$classpathFile" dependency:build-classpath
    Assert-CommandSuccess "Building metadata exporter classpath"

    $dependencyClasspath = Get-Content $classpathFile
    $benchmarkClasspath = "target/classes;$dependencyClasspath"

    java -cp $benchmarkClasspath no.softmuffin.bench.support.BenchmarkMetadataExporter $SignatureMetadataPath $TlsMetadataPath
    Assert-CommandSuccess "Collecting size metadata"
}

function Load-CsvIfExists {
    param([string]$MetadataPath)

    if (-not (Test-Path $MetadataPath)) {
        return @()
    }

    return @(Import-Csv $MetadataPath)
}

function Add-SignatureMetadataToRows {
    param(
        [object[]]$Rows,
        [object[]]$SizeRows
    )

    $byAlgorithmAndPayload = @{}
    $byAlgorithm = @{}

    foreach ($sizeRow in $SizeRows) {
        $algorithmKey = [string]$sizeRow.algorithm
        $payloadKey = [string]$sizeRow.payloadSizeBytes
        $byAlgorithmAndPayload["$algorithmKey|$payloadKey"] = $sizeRow

        if (-not $byAlgorithm.ContainsKey($algorithmKey)) {
            $byAlgorithm[$algorithmKey] = $sizeRow
        }
    }

    foreach ($row in $Rows) {
        $metadata = $null
        $algorithm = Normalize-SignatureLabel $row.algorithm

        if ($algorithm -and $row.payloadSizeBytes) {
            $metadata = $byAlgorithmAndPayload["$algorithm|$($row.payloadSizeBytes)"]
        }

        if ($null -eq $metadata -and $algorithm) {
            $metadata = $byAlgorithm[$algorithm]
        }

        $row | Add-Member -Force -NotePropertyName publicKeyEncodedBits -NotePropertyValue $(if ($metadata) { $metadata.publicKeyEncodedBits } else { $null })
        $row | Add-Member -Force -NotePropertyName algorithmFamily -NotePropertyValue $(if ($metadata) { $metadata.family } else { $null })
        $row | Add-Member -Force -NotePropertyName nistLevel -NotePropertyValue $(if ($metadata) { $metadata.nistLevel } else { $null })
        $row | Add-Member -Force -NotePropertyName parameterSet -NotePropertyValue $(if ($metadata) { $metadata.parameterSet } else { $null })
        $row | Add-Member -Force -NotePropertyName publicKeyEncodedBytes -NotePropertyValue $(if ($metadata) { $metadata.publicKeyEncodedBytes } else { $null })
        $row | Add-Member -Force -NotePropertyName privateKeyEncodedBits -NotePropertyValue $(if ($metadata) { $metadata.privateKeyEncodedBits } else { $null })
        $row | Add-Member -Force -NotePropertyName privateKeyEncodedBytes -NotePropertyValue $(if ($metadata) { $metadata.privateKeyEncodedBytes } else { $null })
        $row | Add-Member -Force -NotePropertyName signatureBytes -NotePropertyValue $(if ($metadata -and $row.payloadSizeBytes) { $metadata.signatureBytes } else { $null })
        $row | Add-Member -Force -NotePropertyName signatureBase64Chars -NotePropertyValue $(if ($metadata -and $row.payloadSizeBytes) { $metadata.signatureBase64Chars } else { $null })
        $row | Add-Member -Force -NotePropertyName tokenBytes -NotePropertyValue $(if ($metadata -and $row.payloadSizeBytes) { $metadata.tokenBytes } else { $null })
        $row | Add-Member -Force -NotePropertyName tokenChars -NotePropertyValue $(if ($metadata -and $row.payloadSizeBytes) { $metadata.tokenChars } else { $null })
    }
}

function Normalize-SignatureLabel {
    param([string]$Algorithm)

    if (-not $Algorithm) {
        return $null
    }

    switch ($Algorithm.ToUpperInvariant()) {
        "RSA" { return "RSA-L1" }
        "EC" { return "EC-L3" }
        "ECC" { return "EC-L3" }
        "ML-DSA" { return "ML-DSA-L3" }
        "SLH-DSA" { return "SLH-DSA-L3" }
        default { return $Algorithm.ToUpperInvariant() }
    }
}

function Add-TlsMetadataToRows {
    param(
        [object[]]$Rows,
        [object[]]$TlsRows
    )

    $byProfile = @{}
    foreach ($tlsRow in $TlsRows) {
        $byProfile[[string]$tlsRow.profile] = $tlsRow
    }

    foreach ($row in $Rows) {
        $metadata = $null

        $profile = Normalize-TlsProfileLabel $row.tlsProfile

        if ($profile) {
            $metadata = $byProfile[$profile]
            $row.tlsProfile = $profile
            if ($row.benchmarkClass -eq "TlsHandshakeBenchmark") {
                $row.algorithm = $profile
            }
        }

        $row | Add-Member -Force -NotePropertyName tlsSupported -NotePropertyValue $(if ($metadata) { $metadata.supported } else { $null })
        $row | Add-Member -Force -NotePropertyName tlsProvider -NotePropertyValue $(if ($metadata) { $metadata.provider } else { $null })
        $row | Add-Member -Force -NotePropertyName tlsProtocol -NotePropertyValue $(if ($metadata) { $metadata.protocol } else { $null })
        $row | Add-Member -Force -NotePropertyName tlsNistLevel -NotePropertyValue $(if ($metadata) { $metadata.nistLevel } else { $null })
        $row | Add-Member -Force -NotePropertyName tlsKeyAgreementNistLevel -NotePropertyValue $(if ($metadata) { $metadata.keyAgreementNistLevel } else { $null })
        $row | Add-Member -Force -NotePropertyName tlsAuthenticationNistLevel -NotePropertyValue $(if ($metadata) { $metadata.authenticationNistLevel } else { $null })
        $row | Add-Member -Force -NotePropertyName tlsEffectiveNistLevel -NotePropertyValue $(if ($metadata) { $metadata.effectiveNistLevel } else { $null })
        $row | Add-Member -Force -NotePropertyName tlsAuthenticationAlgorithm -NotePropertyValue $(if ($metadata) { $metadata.authenticationAlgorithm } else { $null })
        $row | Add-Member -Force -NotePropertyName tlsAuthPublicKeyEncodedBytes -NotePropertyValue $(if ($metadata) { $metadata.authPublicKeyEncodedBytes } else { $null })
        $row | Add-Member -Force -NotePropertyName tlsAuthPrivateKeyEncodedBytes -NotePropertyValue $(if ($metadata) { $metadata.authPrivateKeyEncodedBytes } else { $null })
        $row | Add-Member -Force -NotePropertyName tlsCertificateDerBytes -NotePropertyValue $(if ($metadata) { $metadata.certificateDerBytes } else { $null })
        $row | Add-Member -Force -NotePropertyName tlsNamedGroups -NotePropertyValue $(if ($metadata) { $metadata.namedGroups } else { $null })
        $row | Add-Member -Force -NotePropertyName tlsKeyAgreement -NotePropertyValue $(if ($metadata) { $metadata.keyAgreement } else { $null })
        $row | Add-Member -Force -NotePropertyName tlsClientKeyShareBytes -NotePropertyValue $(if ($metadata) { $metadata.clientKeyShareBytes } else { $null })
        $row | Add-Member -Force -NotePropertyName tlsServerKeyShareBytes -NotePropertyValue $(if ($metadata) { $metadata.serverKeyShareBytes } else { $null })
        $row | Add-Member -Force -NotePropertyName tlsSharedSecretMaterialBytes -NotePropertyValue $(if ($metadata) { $metadata.sharedSecretMaterialBytes } else { $null })
    }
}

function Normalize-TlsProfileLabel {
    param([string]$Profile)

    if (-not $Profile) {
        return $null
    }

    switch ($Profile.ToUpperInvariant()) {
        "RSA" { return "P384-RSA-L1" }
        "RSA-L1" { return "P384-RSA-L1" }
        "ECC" { return "P384-ECDSA-L3" }
        "ECC-L3" { return "P384-ECDSA-L3" }
        "ML-KEM" { return "MLKEM768-RSA-L1" }
        "ML-KEM-L3" { return "MLKEM768-RSA-L1" }
        "X25519-ML-KEM" { return "X25519-MLKEM768-RSA-L1" }
        "X25519-ML-KEM-L3" { return "X25519-MLKEM768-RSA-L1" }
        "ECC-L5" { return "P521-ECDSA-L5" }
        "ML-KEM-L5" { return "MLKEM1024-RSA-L1" }
        "P384-ML-KEM-L5" { return "P384-MLKEM1024-RSA-L1" }
        default { return $Profile.ToUpperInvariant() }
    }
}

function Convert-ToMilliseconds {
    param(
        [double]$Score,
        [string]$Unit
    )

    switch ($Unit) {
        "s/op" { return $Score * 1000.0 }
        "ms/op" { return $Score }
        "us/op" { return $Score / 1000.0 }
        "ns/op" { return $Score / 1000000.0 }
        default { return $null }
    }
}

function Convert-ToMicroseconds {
    param(
        [double]$Score,
        [string]$Unit
    )

    switch ($Unit) {
        "s/op" { return $Score * 1000000.0 }
        "ms/op" { return $Score * 1000.0 }
        "us/op" { return $Score }
        "ns/op" { return $Score / 1000.0 }
        default { return $null }
    }
}

function Format-Number {
    param(
        [Nullable[double]]$Value,
        [int]$Decimals = 3
    )

    if ($null -eq $Value) {
        return ""
    }

    return $Value.ToString("N$Decimals", [Globalization.CultureInfo]::InvariantCulture)
}

function Format-BytesAsKiB {
    param([Nullable[double]]$Bytes)

    if ($null -eq $Bytes) {
        return ""
    }

    return Format-Number ($Bytes / 1024.0) 1
}

function Format-BytesAsMiB {
    param([Nullable[double]]$Bytes)

    if ($null -eq $Bytes) {
        return ""
    }

    return Format-Number ($Bytes / 1048576.0) 2
}

function Get-Scenario {
    param(
        [string]$ClassName,
        [string]$MethodName
    )

    switch ($ClassName) {
        "SignatureKeyGenerationBenchmark" { return "key_generation" }
        "SignatureFullLifecycleBenchmark" { return "full_lifecycle" }
        "SignatureServiceBenchmark" {
            switch ($MethodName) {
                "sign" { return "steady_state_sign" }
                "verify" { return "steady_state_verify" }
                "roundTrip" { return "steady_state_round_trip" }
                default { return "steady_state" }
            }
        }
        "TlsHandshakeBenchmark" {
            switch ($MethodName) {
                "handshakeOnly" { return "tls_handshake" }
                "handshakeAndMessage" { return "tls_handshake_message" }
                default { return "tls" }
            }
        }
        default { return "unknown" }
    }
}

function Convert-Result {
    param([object]$Result)

    $shortName = $Result.benchmark -replace "^no\.softmuffin\.bench\.", ""
    $parts = $shortName -split "\."
    $category = $parts[0]
    $className = $parts[1]
    $methodName = $parts[2]

    $score = [double]$Result.primaryMetric.score
    $scoreUnit = [string]$Result.primaryMetric.scoreUnit
    $scoreError = Get-ObjectValue $Result.primaryMetric "scoreError"
    $scoreConfidence = $Result.primaryMetric.scoreConfidence
    $allocBytesPerOp = Get-MetricValue $Result "gc.alloc.rate.norm"

    $algorithm = Get-ParamValue $Result "algorithm"
    if (-not $algorithm) {
        $algorithm = Get-ParamValue $Result "signatureAlgorithm"
    }
    if (-not $algorithm) {
        $algorithm = Get-ParamValue $Result "handshakeProfile"
    }

    [PSCustomObject]@{
        category = $category
        scenario = Get-Scenario $className $methodName
        benchmarkClass = $className
        method = $methodName
        benchmark = $shortName
        algorithm = $algorithm
        payloadSizeBytes = Get-ParamValue $Result "payloadSizeBytes"
        tlsProfile = Get-ParamValue $Result "handshakeProfile"
        messageSizeBytes = Get-ParamValue $Result "messageSizeBytes"
        mode = $Result.mode
        forks = $Result.forks
        warmupIterations = $Result.warmupIterations
        measurementIterations = $Result.measurementIterations
        score = $score
        scoreUnit = $scoreUnit
        scoreMsPerOp = Convert-ToMilliseconds $score $scoreUnit
        scoreUsPerOp = Convert-ToMicroseconds $score $scoreUnit
        scoreError = $scoreError
        relativeErrorPercent = if ($score -ne 0 -and $null -ne $scoreError) { ([double]$scoreError / $score) * 100.0 } else { $null }
        confidenceLow = $scoreConfidence[0]
        confidenceHigh = $scoreConfidence[1]
        p50 = Get-PrimaryPercentile $Result "50.0"
        p90 = Get-PrimaryPercentile $Result "90.0"
        p95 = Get-PrimaryPercentile $Result "95.0"
        p99 = Get-PrimaryPercentile $Result "99.0"
        allocRateMbSec = Get-MetricValue $Result "gc.alloc.rate"
        allocBytesPerOp = $allocBytesPerOp
        allocKiBPerOp = if ($allocBytesPerOp) { $allocBytesPerOp / 1024.0 } else { $null }
        allocMiBPerOp = if ($allocBytesPerOp) { $allocBytesPerOp / 1048576.0 } else { $null }
        gcCount = Get-MetricValue $Result "gc.count"
        gcTimeMs = Get-MetricValue $Result "gc.time"
        jdkVersion = $Result.jdkVersion
        jmhVersion = $Result.jmhVersion
    }
}

function Add-Line {
    param([string]$Line = "")

    $script:reportLines.Add($Line) | Out-Null
}

function Add-HowToReadSection {
    Add-Line "## How To Read The Units"
    Add-Line
    Add-Line "| Field | Unit | Meaning |"
    Add-Line "| --- | --- | --- |"
    Add-Line '| Score | `ms/op`, `us/op`, or `ns/op` | Average time for one benchmark operation. Lower is faster. |'
    Add-Line '| `ms/op` | milliseconds per operation | 1 millisecond is 1/1,000 of a second. Good for slower operations like key generation, full lifecycle, and TLS handshakes. |'
    Add-Line '| `us/op` | microseconds per operation | 1 microsecond is 1/1,000,000 of a second. Good for smaller steady-state sign and verify operations. 1,000 us = 1 ms. |'
    Add-Line "| Error | same as score | JMH uncertainty around the score. If error is large compared with the score, the result is noisy. |"
    Add-Line "| Confidence low/high | same as score | The estimated interval where the true average likely sits. Narrower is more stable. |"
    Add-Line "| p50, p90, p95, p99 | same as score | Percentiles of the measured iterations. p50 is the middle value; p99 shows high-end slow measurements. |"
    Add-Line '| Allocation | `B/op`, `KiB/op`, or `MiB/op` | Memory allocated for one operation. Lower means less memory pressure. |'
    Add-Line '| `B/op` | bytes per operation | Raw allocation count from JMH''s `gc.alloc.rate.norm`. |'
    Add-Line '| `KiB/op` | kibibytes per operation | Bytes divided by 1,024. Used when allocations are medium-sized. |'
    Add-Line '| `MiB/op` | mebibytes per operation | Bytes divided by 1,048,576. Used when allocations are large. |'
    Add-Line '| `gc.alloc.rate` | MB/sec | Allocation throughput during the benchmark. Useful, but usually less direct than allocation per operation. |'
    Add-Line '| `gc.count` | counts | Number of garbage collections during the measured run. This is not per operation. |'
    Add-Line '| `gc.time` | ms | Total time spent in garbage collection during the measured run. This is not per operation. |'
    Add-Line
    Add-Line 'In most comparisons, start with score and allocation per operation. For computational cost, read score, allocation per operation, GC count, and GC time together.'
    Add-Line
    Add-Line 'For example, `4 ms/op` means one operation takes about four milliseconds, while `600 KiB/op` means one operation allocates about 600 kibibytes of memory.'
    Add-Line
}

function Add-SignatureSizeTable {
    param([object[]]$SizeRows)

    if ($SizeRows.Count -eq 0) {
        return
    }

    Add-Line "## Signatures: Key And Signature Sizes"
    Add-Line
    Add-Line "These values are metadata, not timing results. They show the size cost that belongs beside the benchmark timings."
    Add-Line
    Add-Line "| Algorithm | Family | NIST level | Parameter set | Payload bytes | Public key bytes | Private key bytes | Signature bytes | JWT bytes |"
    Add-Line "| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |"

    $SizeRows |
        Sort-Object algorithm, { [int]$_.payloadSizeBytes } |
        ForEach-Object {
            Add-Line "| $($_.algorithm) | $($_.family) | $($_.nistLevel) | $($_.parameterSet) | $($_.payloadSizeBytes) | $($_.publicKeyEncodedBytes) | $($_.privateKeyEncodedBytes) | $($_.signatureBytes) | $($_.tokenBytes) |"
        }

    Add-Line
}

function Add-KeyGenerationTable {
    param([object[]]$Rows)

    Add-Line "## Signatures: Key Generation Timings"
    Add-Line
    Add-Line "| Algorithm | NIST level | Parameter set | Score (ms/op) | Error | Public key bytes | Private key bytes | Alloc (MiB/op) | GC count | GC time (ms) |"
    Add-Line "| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"

    $Rows |
        Where-Object { $_.scenario -eq "key_generation" } |
        Sort-Object algorithm |
        ForEach-Object {
            Add-Line "| $($_.algorithm) | $($_.nistLevel) | $($_.parameterSet) | $(Format-Number $_.scoreMsPerOp 3) | $(Format-Number $_.scoreError 3) | $($_.publicKeyEncodedBytes) | $($_.privateKeyEncodedBytes) | $(Format-BytesAsMiB $_.allocBytesPerOp) | $(Format-Number $_.gcCount 0) | $(Format-Number $_.gcTimeMs 0) |"
        }

    Add-Line
}

function Add-FullLifecycleTable {
    param([object[]]$Rows)

    Add-Line "## Signatures: Full Lifecycle Timings"
    Add-Line
    Add-Line "Fresh key generation, signing with the fresh private key, and verification with the matching fresh public key."
    Add-Line
    Add-Line "| Algorithm | NIST level | Payload bytes | Score (ms/op) | Error | Signature bytes | JWT bytes | Alloc (MiB/op) | GC count | GC time (ms) |"
    Add-Line "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"

    $Rows |
        Where-Object { $_.scenario -eq "full_lifecycle" } |
        Sort-Object algorithm, { [int]$_.payloadSizeBytes } |
        ForEach-Object {
            Add-Line "| $($_.algorithm) | $($_.nistLevel) | $($_.payloadSizeBytes) | $(Format-Number $_.scoreMsPerOp 3) | $(Format-Number $_.scoreError 3) | $($_.signatureBytes) | $($_.tokenBytes) | $(Format-BytesAsMiB $_.allocBytesPerOp) | $(Format-Number $_.gcCount 0) | $(Format-Number $_.gcTimeMs 0) |"
        }

    Add-Line
}

function Add-SteadyStateSignatureTable {
    param([object[]]$Rows)

    Add-Line "## Signatures: Steady-State Timings"
    Add-Line
    Add-Line "Configured reusable keys. Scores are shown in microseconds because these operations are much smaller than full lifecycle."
    Add-Line
    Add-Line "| Method | Algorithm | NIST level | Payload bytes | Score (us/op) | Error | Signature bytes | JWT bytes | Alloc (KiB/op) | GC count | GC time (ms) |"
    Add-Line "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"

    $Rows |
        Where-Object { $_.benchmarkClass -eq "SignatureServiceBenchmark" } |
        Sort-Object method, algorithm, { [int]$_.payloadSizeBytes } |
        ForEach-Object {
            Add-Line "| $($_.method) | $($_.algorithm) | $($_.nistLevel) | $($_.payloadSizeBytes) | $(Format-Number $_.scoreUsPerOp 3) | $(Format-Number $_.scoreError 3) | $($_.signatureBytes) | $($_.tokenBytes) | $(Format-BytesAsKiB $_.allocBytesPerOp) | $(Format-Number $_.gcCount 0) | $(Format-Number $_.gcTimeMs 0) |"
        }

    Add-Line
}

function Add-TlsTables {
    param(
        [object[]]$Rows,
        [object[]]$TlsRows
    )

    if ($TlsRows.Count -gt 0) {
        Add-Line "## TLS: Profile Size Metadata"
        Add-Line
        Add-Line "Authentication key and certificate sizes are exported from generated benchmark credentials. Key-share sizes are TLS named-group metadata; JSSE does not expose the actual ephemeral key-share bytes from the negotiated session. The effective level is the lower of the authentication level and the key-agreement level."
        Add-Line
        Add-Line "| Profile | Provider | KEX level | Auth level | Effective level | Authentication | Auth public key bytes | Auth private key bytes | Certificate bytes | Named group | Key agreement | Client key share bytes | Server key share bytes | Shared secret material bytes |"
        Add-Line "| --- | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | --- | --- | ---: | ---: | ---: |"

        $TlsRows |
            Where-Object { $_.supported -eq "true" } |
            Sort-Object profile |
            ForEach-Object {
                Add-Line "| $($_.profile) | $($_.provider) | $($_.keyAgreementNistLevel) | $($_.authenticationNistLevel) | $($_.effectiveNistLevel) | $($_.authenticationAlgorithm) | $($_.authPublicKeyEncodedBytes) | $($_.authPrivateKeyEncodedBytes) | $($_.certificateDerBytes) | $($_.namedGroups) | $($_.keyAgreement) | $($_.clientKeyShareBytes) | $($_.serverKeyShareBytes) | $($_.sharedSecretMaterialBytes) |"
            }

        Add-Line
    }

    Add-Line "## TLS: Handshake Timings"
    Add-Line
    Add-Line "| Profile | KEX level | Auth level | Effective level | Score (ms/op) | Error | Auth public key bytes | Certificate bytes | Client key share bytes | Server key share bytes | Alloc (KiB/op) | GC count | GC time (ms) |"
    Add-Line "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"

    $Rows |
        Where-Object { $_.scenario -eq "tls_handshake" } |
        Sort-Object tlsProfile |
        ForEach-Object {
            Add-Line "| $($_.tlsProfile) | $($_.tlsKeyAgreementNistLevel) | $($_.tlsAuthenticationNistLevel) | $($_.tlsEffectiveNistLevel) | $(Format-Number $_.scoreMsPerOp 3) | $(Format-Number $_.scoreError 3) | $($_.tlsAuthPublicKeyEncodedBytes) | $($_.tlsCertificateDerBytes) | $($_.tlsClientKeyShareBytes) | $($_.tlsServerKeyShareBytes) | $(Format-BytesAsKiB $_.allocBytesPerOp) | $(Format-Number $_.gcCount 0) | $(Format-Number $_.gcTimeMs 0) |"
        }

    Add-Line
    Add-Line "## TLS: Handshake And Message Timings"
    Add-Line
    Add-Line "| Profile | KEX level | Auth level | Effective level | Message bytes | Score (ms/op) | Error | Auth public key bytes | Certificate bytes | Client key share bytes | Server key share bytes | Alloc (KiB/op) | GC count | GC time (ms) |"
    Add-Line "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"

    $Rows |
        Where-Object { $_.scenario -eq "tls_handshake_message" } |
        Sort-Object tlsProfile, { [int]$_.messageSizeBytes } |
        ForEach-Object {
            Add-Line "| $($_.tlsProfile) | $($_.tlsKeyAgreementNistLevel) | $($_.tlsAuthenticationNistLevel) | $($_.tlsEffectiveNistLevel) | $($_.messageSizeBytes) | $(Format-Number $_.scoreMsPerOp 3) | $(Format-Number $_.scoreError 3) | $($_.tlsAuthPublicKeyEncodedBytes) | $($_.tlsCertificateDerBytes) | $($_.tlsClientKeyShareBytes) | $($_.tlsServerKeyShareBytes) | $(Format-BytesAsKiB $_.allocBytesPerOp) | $(Format-Number $_.gcCount 0) | $(Format-Number $_.gcTimeMs 0) |"
        }

    Add-Line
}

function Add-TopAllocationTable {
    param([object[]]$Rows)

    Add-Line "## Highest Allocation Per Operation"
    Add-Line
    Add-Line "| Benchmark | Algorithm/Profile | Size | Score | Alloc (MiB/op) |"
    Add-Line "| --- | --- | ---: | ---: | ---: |"

    $Rows |
        Where-Object { $null -ne $_.allocBytesPerOp } |
        Sort-Object allocBytesPerOp -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            $name = "$($_.benchmarkClass).$($_.method)"
            $algo = if ($_.tlsProfile) { $_.tlsProfile } else { $_.algorithm }
            $size = if ($_.payloadSizeBytes) { $_.payloadSizeBytes } elseif ($_.messageSizeBytes) { $_.messageSizeBytes } else { "" }
            $score = "$(Format-Number $_.score 3) $($_.scoreUnit)"
            Add-Line "| $name | $algo | $size | $score | $(Format-BytesAsMiB $_.allocBytesPerOp) |"
        }

    Add-Line
}

function Add-HighUncertaintyTable {
    param([object[]]$Rows)

    $noisyRows = @($Rows |
        Where-Object { $null -ne $_.relativeErrorPercent -and $_.relativeErrorPercent -ge 50.0 } |
        Sort-Object relativeErrorPercent -Descending)

    if ($noisyRows.Count -eq 0) {
        return
    }

    Add-Line "## Highest Measurement Uncertainty"
    Add-Line
    Add-Line "These rows have JMH error greater than or equal to 50% of the measured score. They are useful warning signs, not stable headline numbers."
    Add-Line
    Add-Line "| Benchmark | Algorithm/Profile | Size | Score | Error | Error / score |"
    Add-Line "| --- | --- | ---: | ---: | ---: | ---: |"

    $noisyRows |
        Select-Object -First 12 |
        ForEach-Object {
            $name = "$($_.benchmarkClass).$($_.method)"
            $algo = if ($_.tlsProfile) { $_.tlsProfile } else { $_.algorithm }
            $size = if ($_.payloadSizeBytes) { $_.payloadSizeBytes } elseif ($_.messageSizeBytes) { $_.messageSizeBytes } else { "" }
            $score = "$(Format-Number $_.score 3) $($_.scoreUnit)"
            $error = "$(Format-Number $_.scoreError 3) $($_.scoreUnit)"
            Add-Line "| $name | $algo | $size | $score | $error | $(Format-Number $_.relativeErrorPercent 1)% |"
        }

    Add-Line
}

$resolvedInputPath = Resolve-InputPath $InputPath
$results = Get-Content $resolvedInputPath | ConvertFrom-Json
$rows = @($results | ForEach-Object { Convert-Result $_ })

if (-not $OutputDir) {
    $OutputDir = Split-Path $resolvedInputPath -Parent
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$baseName = [IO.Path]::GetFileNameWithoutExtension($resolvedInputPath)
$summaryCsv = Join-Path $OutputDir "$baseName-summary.csv"
$reportMarkdown = Join-Path $OutputDir "$baseName-report.md"
$signatureSizeMetadataCsv = Join-Path $OutputDir "$baseName-signature-size-metadata.csv"
$tlsSizeMetadataCsv = Join-Path $OutputDir "$baseName-tls-size-metadata.csv"

if (-not $SkipSizeMetadata) {
    Invoke-SizeMetadataExport $signatureSizeMetadataCsv $tlsSizeMetadataCsv
}

$signatureSizeRows = Load-CsvIfExists $signatureSizeMetadataCsv
$tlsSizeRows = Load-CsvIfExists $tlsSizeMetadataCsv
Add-SignatureMetadataToRows $rows $signatureSizeRows
Add-TlsMetadataToRows $rows $tlsSizeRows

$rows |
    Sort-Object category, benchmarkClass, method, algorithm, { [int]($_.payloadSizeBytes -as [int]) }, tlsProfile, { [int]($_.messageSizeBytes -as [int]) } |
    Export-Csv -NoTypeInformation -Path $summaryCsv

$script:reportLines = New-Object System.Collections.Generic.List[string]
$first = $results[0]

Add-Line "# Benchmark Report"
Add-Line
Add-Line ('- Source: `{0}`' -f $resolvedInputPath)
Add-Line "- JMH: $($first.jmhVersion)"
Add-Line "- JDK: $($first.jdkVersion)"
Add-Line "- Entries: $($rows.Count)"
Add-Line ("- Generated: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
Add-Line
Add-Line 'Score is average time per operation. Allocation columns come from the JMH `gc` profiler and are usually the easiest profiler values to compare across algorithms.'
Add-Line

Add-HowToReadSection
Add-SignatureSizeTable $signatureSizeRows
Add-KeyGenerationTable $rows
Add-FullLifecycleTable $rows
Add-SteadyStateSignatureTable $rows
Add-TlsTables $rows $tlsSizeRows
Add-HighUncertaintyTable $rows
Add-TopAllocationTable $rows

Set-Content -Path $reportMarkdown -Value $reportLines -Encoding utf8

Write-Host "Summary CSV: $summaryCsv"
if ($signatureSizeRows.Count -gt 0) {
    Write-Host "Signature size metadata CSV: $signatureSizeMetadataCsv"
}
if ($tlsSizeRows.Count -gt 0) {
    Write-Host "TLS size metadata CSV: $tlsSizeMetadataCsv"
}
Write-Host "Markdown report: $reportMarkdown"
