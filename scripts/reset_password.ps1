<#
.SYNOPSIS
    Reseta a senha de um usuário no Active Directory.
.PARAMETER Login
    Login do usuário (SamAccountName)
.PARAMETER NovaSenha
    Nova senha para o usuário
.PARAMETER ForcarTroca
    Se True, força o usuário a trocar a senha no próximo login
.PARAMETER DryRun
    Se True, simula a operação sem executar
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Login,
    
    [Parameter(Mandatory = $true)]
    [string]$NovaSenha,
    
    [Parameter(Mandatory = $false)]
    [switch]$ForcarTroca = $true,
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun = $false
)

$resultado = @{
    sucesso  = $false
    mensagem = ""
    dados    = @{
        login        = $Login
        forcar_troca = $ForcarTroca.IsPresent
    }
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    
    # Verificar se usuário existe
    $usuario = Get-ADUser -Identity $Login -ErrorAction Stop
    
    if ($DryRun) {
        $resultado.sucesso = $true
        $resultado.mensagem = "[DRY-RUN] Senha do usuário '$Login' seria resetada."
        $resultado.dados.dry_run = $true
    }
    else {
        # Converter senha
        $senhaSecura = ConvertTo-SecureString -String $NovaSenha -AsPlainText -Force
        
        # Resetar senha
        Set-ADAccountPassword -Identity $Login -NewPassword $senhaSecura -Reset -ErrorAction Stop
        
        # Forçar troca se solicitado
        if ($ForcarTroca) {
            Set-ADUser -Identity $Login -ChangePasswordAtLogon $true -ErrorAction Stop
        }
        
        $resultado.sucesso = $true
        $resultado.mensagem = "Senha do usuário '$Login' resetada com sucesso!"
    }
    
}
catch {
    $resultado.sucesso = $false
    $resultado.mensagem = "ERRO: $($_.Exception.Message)"
}

$resultado | ConvertTo-Json -Compress
