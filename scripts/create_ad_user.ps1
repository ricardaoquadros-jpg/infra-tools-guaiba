<#
.SYNOPSIS
    Cria um usuário no Active Directory com as configurações especificadas.
.DESCRIPTION
    Script para criação automatizada de usuários no AD do domínio GUAIBA.LOCAL.
    Requer módulo ActiveDirectory instalado e permissões de administrador.
.PARAMETER NomeCompleto
    Nome completo do usuário (ex: "João da Silva Santos")
.PARAMETER Login
    Login do usuário no formato nome.sobrenome
.PARAMETER Setor
    Setor do usuário (Administrativo, Educacao, Saude)
.PARAMETER Cargo
    Cargo do usuário
.PARAMETER Senha
    Senha inicial do usuário
.PARAMETER OU
    Caminho da OU onde o usuário será criado
.PARAMETER Grupos
    Lista de grupos separados por vírgula
.PARAMETER CPF
    CPF do usuário (será usado como Description)
.PARAMETER Telefone
    Número de telefone do usuário
.PARAMETER DryRun
    Se True, simula a criação sem executar de fato
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$NomeCompleto,
    
    [Parameter(Mandatory = $true)]
    [string]$Login,
    
    [Parameter(Mandatory = $true)]
    [string]$Setor,
    
    [Parameter(Mandatory = $true)]
    [string]$Cargo,
    
    [Parameter(Mandatory = $true)]
    [string]$Senha,
    
    [Parameter(Mandatory = $true)]
    [string]$OU,
    
    [Parameter(Mandatory = $false)]
    [string]$Grupos = "",
    
    [Parameter(Mandatory = $false)]
    [string]$CPF = "",
    
    [Parameter(Mandatory = $false)]
    [string]$Telefone = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun = $false
)

# Resultado padrão
$resultado = @{
    sucesso  = $false
    mensagem = ""
    dados    = @{
        login    = $Login
        nome     = $NomeCompleto
        setor    = $Setor
        cargo    = $Cargo
        ou       = $OU
        email    = "$Login@guaiba.rs.gov.br"
        telefone = $Telefone
        cpf      = $CPF
        grupos   = @()
    }
}

try {
    # Verificar se o módulo ActiveDirectory está disponível
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "Módulo ActiveDirectory não está instalado. Instale o RSAT."
    }
    
    Import-Module ActiveDirectory -ErrorAction Stop
    
    # Separar nome e sobrenome
    # First name = primeiro nome
    # Surname = do segundo nome em diante (ex: "Roberto Etter dos Santos" -> Surname = "Etter dos Santos")
    $partes = $NomeCompleto.Trim() -split '\s+'
    $primeiroNome = $partes[0]
    
    # Sobrenome inclui todos os nomes após o primeiro
    if ($partes.Count -gt 1) {
        $sobrenome = ($partes[1..($partes.Count - 1)]) -join ' '
    }
    else {
        $sobrenome = ""
    }
    
    # Email no formato login@guaiba.rs.gov.br
    $email = "$Login@guaiba.rs.gov.br"
    
    # Verificar se usuário já existe
    $usuarioExistente = Get-ADUser -Filter "SamAccountName -eq '$Login'" -ErrorAction SilentlyContinue
    if ($usuarioExistente) {
        throw "Usuário '$Login' já existe no Active Directory."
    }
    
    # Verificar se OU existe
    try {
        Get-ADOrganizationalUnit -Identity $OU -ErrorAction Stop | Out-Null
    }
    catch {
        throw "OU não encontrada: $OU"
    }
    
    # Converter senha para SecureString
    $senhaSecura = ConvertTo-SecureString -String $Senha -AsPlainText -Force
    
    # Parâmetros do novo usuário
    $parametrosUsuario = @{
        Name                  = $NomeCompleto
        GivenName             = $primeiroNome
        Surname               = $sobrenome
        SamAccountName        = $Login
        UserPrincipalName     = "$Login@guaiba.rs.gov.br"
        DisplayName           = $NomeCompleto
        Description           = $CPF                    # CPF no campo Description
        Title                 = $Cargo                        # Cargo no campo Title
        Office                = $Cargo                       # Cargo no campo Office
        Department            = $Setor
        EmailAddress          = $email                 # Email
        Path                  = $OU
        AccountPassword       = $senhaSecura
        Enabled               = $true
        ChangePasswordAtLogon = $true
    }
    
    # Adicionar telefone se fornecido
    if ($Telefone -ne "") {
        $parametrosUsuario['OfficePhone'] = $Telefone
    }
    
    if ($DryRun) {
        $resultado.sucesso = $true
        $resultado.mensagem = "[DRY-RUN] Usuário '$Login' seria criado com sucesso."
        $resultado.dados.dry_run = $true
        $resultado.dados.primeiro_nome = $primeiroNome
        $resultado.dados.sobrenome = $sobrenome
    }
    else {
        # Criar o usuário
        New-ADUser @parametrosUsuario -ErrorAction Stop
        
        # Adicionar aos grupos
        if ($Grupos -ne "") {
            $listaGrupos = $Grupos -split ','
            foreach ($grupo in $listaGrupos) {
                $grupoTrimmed = $grupo.Trim()
                if ($grupoTrimmed -ne "") {
                    try {
                        Add-ADGroupMember -Identity $grupoTrimmed -Members $Login -ErrorAction Stop
                        $resultado.dados.grupos += $grupoTrimmed
                    }
                    catch {
                        Write-Warning "Não foi possível adicionar ao grupo '$grupoTrimmed': $_"
                    }
                }
            }
        }
        
        $resultado.sucesso = $true
        $resultado.mensagem = "Usuário '$Login' criado com sucesso!"
        $resultado.dados.primeiro_nome = $primeiroNome
        $resultado.dados.sobrenome = $sobrenome
    }
    
}
catch {
    $resultado.sucesso = $false
    $resultado.mensagem = "ERRO: $($_.Exception.Message)"
}

# Retornar resultado como JSON
$resultado | ConvertTo-Json -Compress
