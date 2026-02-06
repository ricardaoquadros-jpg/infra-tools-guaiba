<#
.SYNOPSIS
    Verifica se o ambiente está preparado para operações no AD.
.DESCRIPTION
    Verifica módulo ActiveDirectory, conectividade com o domínio e permissões.
#>

$resultado = @{
    modulo_instalado = $false
    conectado_dominio = $false
    dominio = ""
    usuario_atual = ""
    is_admin = $false
    mensagens = @()
}

try {
    # Verificar usuário atual
    $resultado.usuario_atual = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    
    # Verificar se é administrador
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $resultado.is_admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $resultado.is_admin) {
        $resultado.mensagens += "AVISO: Aplicativo não está sendo executado como Administrador."
    }
    
    # Verificar módulo ActiveDirectory
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        $resultado.modulo_instalado = $true
        Import-Module ActiveDirectory -ErrorAction Stop
        $resultado.mensagens += "OK: Módulo ActiveDirectory disponível."
    } else {
        $resultado.mensagens += "ERRO: Módulo ActiveDirectory não instalado. Instale o RSAT."
    }
    
    # Verificar conectividade com domínio
    try {
        $dominio = Get-ADDomain -ErrorAction Stop
        $resultado.conectado_dominio = $true
        $resultado.dominio = $dominio.DNSRoot
        $resultado.mensagens += "OK: Conectado ao domínio $($dominio.DNSRoot)."
    } catch {
        $resultado.mensagens += "ERRO: Não foi possível conectar ao domínio. Verifique a rede."
    }
    
} catch {
    $resultado.mensagens += "ERRO: $($_.Exception.Message)"
}

$resultado | ConvertTo-Json -Compress
