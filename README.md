# Infra Tools Guaíba

Aplicativo desktop portátil para automação de TI da Prefeitura de Guaíba.

## 🚀 Funcionalidades

- ✅ **Criação de usuários no AD** com todos os campos padrão
- ✅ **Importação de email** - cola o email e extrai dados automaticamente
- ✅ **Verificação prévia** - checa se usuário existe/desativado/similar
- ✅ **Interface de 3 passos** - fluxo visual e sequencial
- ✅ **Scripts PowerShell** - reset de senha, desabilitar usuário
- ✅ **Conexão remota** - integração com mRemoteNG/RDP
- ✅ **Logs de auditoria** - histórico completo de ações

## 📋 Campos do AD

| Campo AD | Origem |
|----------|--------|
| First name | Primeiro nome |
| Last name | Demais nomes |
| Display name | Nome completo |
| Email | login@guaiba.rs.gov.br |
| Telephone | Telefone |
| Office | Cargo |
| Description | CPF |

## 🔧 Requisitos

- Python 3.8+
- Windows com PowerShell
- Módulo ActiveDirectory (RSAT)

## 📦 Instalação

```powershell
# Clonar repositório
git clone https://github.com/ricardaoquadros-jpg/infra-tools-guaiba.git

# Executar
cd infra-tools-guaiba
python main.py
```

## 📧 Formato de Email Suportado

```
NOME: Roberto Etter dos Santos
CPF: 419.172.430-49
TELEFONE: (51) 99918-7828
SETOR: Educação
CARGO: Supervisor Administrativo
```

## 🛠️ Gerar Executável

```powershell
.\build.bat
# Resultado: dist\InfraToolsGuaiba.exe
```

## 📁 Estrutura

```
infra-tools-guaiba/
├── main.py              # Aplicação principal
├── config/
│   └── settings.json    # Configurações (OUs, grupos)
├── scripts/
│   ├── create_ad_user.ps1
│   ├── verify_user.ps1
│   └── ...
├── logs/                # Logs de auditoria
└── build.bat            # Script para gerar .exe
```

## 📄 Licença

MIT License - Prefeitura Municipal de Guaíba
