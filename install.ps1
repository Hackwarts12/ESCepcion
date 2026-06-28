param(
  [string]$PythonCmd = "python",
  [switch]$NoVenv,
  [switch]$UserInstall,
  [switch]$UpgradePip,
  [string]$Requirements = "requirements.txt"
)

$ErrorActionPreference = "Stop"

function Write-Section([string]$Title) {
  Write-Host ""
  Write-Host "=== $Title ===" -ForegroundColor Cyan
}

function Fail([string]$Msg) {
  Write-Host "[ERROR] $Msg" -ForegroundColor Red
  exit 1
}

Write-Section "ESCepcion installer"

# Validate repo layout
if (!(Test-Path -Path $Requirements)) {
  Fail "No se encontró '$Requirements' en el directorio actual. Ejecuta este script desde la carpeta raíz del proyecto."
}
if (!(Test-Path -Path "main.py")) {
  Fail "No se encontró 'main.py'. Ejecuta este script desde la carpeta raíz del proyecto (donde está main.py)."
}

# Validate Python availability
Write-Section "Validando Python"
try {
  $pyVersion = & $PythonCmd -c "import sys; print(sys.version)" 2>$null
} catch {
  Fail "No pude ejecutar '$PythonCmd'. Instala Python 3.10+ y/o ajusta -PythonCmd (ej: -PythonCmd py)."
}

try {
  $pyVerTuple = & $PythonCmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')" 2>$null
  $major,$minor,$patch = $pyVerTuple.Split('.')
  $major = [int]$major
  $minor = [int]$minor
} catch {
  Fail "No pude leer la versión de Python."
}

Write-Host "Python: $pyVersion" -ForegroundColor Green
if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 10)) {
  Fail "Se requiere Python 3.10+ (detectado: $pyVerTuple)."
}

$venvPath = ".venv"
$pythonExe = $PythonCmd

if (-not $NoVenv) {
  Write-Section "Creando/Usando venv"
  if (!(Test-Path -Path $venvPath)) {
    & $PythonCmd -m venv $venvPath
  }
  $pythonExe = Join-Path $venvPath "Scripts\python.exe"
  if (!(Test-Path -Path $pythonExe)) {
    Fail "No encontré el python del venv en: $pythonExe"
  }
  Write-Host "Usando venv: $venvPath" -ForegroundColor Green
} else {
  Write-Host "NoVenv: instalando en el Python del sistema ($PythonCmd)" -ForegroundColor Yellow
}

if ($UpgradePip) {
  Write-Section "Actualizando pip/setuptools/wheel"
  & $pythonExe -m pip install --upgrade pip setuptools wheel
}

Write-Section "Instalando dependencias"
$pipArgs = @("-m","pip","install","-r",$Requirements)
if ($UserInstall) {
  $pipArgs += "--user"
}

& $pythonExe @pipArgs

Write-Section "Verificación rápida (imports)"
& $pythonExe -c "import ldap3, impacket, colorama, jinja2, plotly; print('OK: imports')"

Write-Section "Listo"
Write-Host "Siguiente paso:" -ForegroundColor Green
if (-not $NoVenv) {
  Write-Host "  1) Activar venv: .\.venv\Scripts\Activate.ps1" -ForegroundColor Green
  Write-Host "  2) Ejecutar: python main.py" -ForegroundColor Green
} else {
  Write-Host "  Ejecutar: $PythonCmd main.py" -ForegroundColor Green
}
Write-Host ""
