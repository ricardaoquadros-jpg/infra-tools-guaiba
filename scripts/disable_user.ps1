<#
.SYNOPSIS
    Desabilita um usuário no Active Directory.
.PARAMETER Login
    Login do usuário (SamAccountName)
.PARAMETER DryRun
    Se True, simula a operação sem executar
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Login,
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun = $false
)

$resultado = @{
    sucesso  = $false
    mensagem = ""
    dados    = @{
        login = $Login
    }
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    
    # Verificar se usuário existe
    $usuario = Get-ADUser -Identity $Login -Properties Enabled -ErrorAction Stop
    
    if (-not $usuario.Enabled) {
        $resultado.sucesso = $true
        $resultado.mensagem = "Usuário '$Login' já está desabilitado."
        $resultado.dados.ja_desabilitado = $true
    }
    elseif ($DryRun) {
        $resultado.sucesso = $true
        $resultado.mensagem = "[DRY-RUN] Usuário '$Login' seria desabilitado."
        $resultado.dados.dry_run = $true
    }
    else {
        # Desabilitar usuário
        Disable-ADAccount -Identity $Login -ErrorAction Stop
        
        $resultado.sucesso = $true
        $resultado.mensagem = "Usuário '$Login' desabilitado com sucesso!"
    }
    
}
catch {
    $resultado.sucesso = $false
    $resultado.mensagem = "ERRO: $($_.Exception.Message)"
}

$resultado | ConvertTo-Json -Compress
