# Generate src\viewer_html.h from web\viewer.html so the web UI can be compiled
# into the binary (that is what makes chainlite.exe portable — no web\ folder needed).
#
# MSVC caps a single string literal at 16380 bytes, so the page is emitted as an
# array of raw-string chunks that are concatenated once at runtime.
param(
  [string]$In  = "$PSScriptRoot\..\web\viewer.html",
  [string]$Out = "$PSScriptRoot\..\src\viewer_html.h",
  [int]$Chunk  = 5000
)
$ErrorActionPreference = "Stop"

if (-not (Test-Path $In)) { Write-Error "missing $In"; exit 1 }
$html = Get-Content -Raw -Encoding UTF8 $In

# The delimiter must not appear in the payload, or a literal would terminate early.
$delim = "CLVIEWER"
if ($html.Contains(")$delim`"")) { Write-Error "delimiter collision in viewer.html"; exit 1 }

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("// GENERATED FILE - do not edit. Source: web/viewer.html")
[void]$sb.AppendLine("// Regenerate with: powershell -File tools\embed.ps1   (build.bat does this automatically)")
[void]$sb.AppendLine("#pragma once")
[void]$sb.AppendLine("#include <string>")
[void]$sb.AppendLine("static const char* const VIEWER_HTML_PARTS[] = {")

$i = 0
while ($i -lt $html.Length) {
  $len = [Math]::Min($Chunk, $html.Length - $i)
  # Never split a surrogate pair.
  if ($i + $len -lt $html.Length -and [char]::IsHighSurrogate($html[$i + $len - 1])) { $len++ }
  $part = $html.Substring($i, $len)
  [void]$sb.AppendLine("R`"$delim($part)$delim`",")
  $i += $len
}

[void]$sb.AppendLine("};")
[void]$sb.AppendLine("inline const std::string& viewer_html() {")
[void]$sb.AppendLine("    static const std::string s = [] {")
[void]$sb.AppendLine("        std::string t;")
[void]$sb.AppendLine("        for (const char* p : VIEWER_HTML_PARTS) t += p;")
[void]$sb.AppendLine("        return t;")
[void]$sb.AppendLine("    }();")
[void]$sb.AppendLine("    return s;")
[void]$sb.AppendLine("}")

$dir = Split-Path -Parent $Out
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
Set-Content -Path $Out -Value $sb.ToString() -Encoding UTF8 -NoNewline
$kb = [math]::Round((Get-Item $In).Length / 1KB, 1)
Write-Host "embed: web\viewer.html ($kb KB) -> src\viewer_html.h"
