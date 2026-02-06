@echo off
echo ========================================
echo   Infra Tools Guaiba - Build Portavel
echo ========================================
echo.

REM Verificar se Python está instalado
python --version >nul 2>&1
if errorlevel 1 (
    echo ERRO: Python nao encontrado. Instale o Python 3.8 ou superior.
    pause
    exit /b 1
)

echo [1/3] Instalando dependencias...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERRO: Falha ao instalar dependencias.
    pause
    exit /b 1
)

echo.
echo [2/3] Gerando executavel...
pyinstaller infra_tools.spec --noconfirm
if errorlevel 1 (
    echo ERRO: Falha ao gerar executavel.
    pause
    exit /b 1
)

echo.
echo [3/3] Copiando arquivos de configuracao...
if not exist "dist\config" mkdir "dist\config"
copy /Y "config\settings.json" "dist\config\"

if not exist "dist\scripts" mkdir "dist\scripts"
copy /Y "scripts\*.ps1" "dist\scripts\"

echo.
echo ========================================
echo   BUILD CONCLUIDO COM SUCESSO!
echo ========================================
echo.
echo O executavel esta em: dist\InfraToolsGuaiba.exe
echo.
echo Para distribuir, copie toda a pasta 'dist' para o local desejado.
echo.
pause
