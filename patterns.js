window.SECRET_FINDER_DATA = {
  "patterns": [
    {
      "name": "AWS Access Key ID",
      "regex": "\\bAKIA[0-9A-Z]{16}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 20,
      "maxLength": 20
    },
    {
      "name": "AWS Secret Access Key",
      "regex": "aws_secret_access_key[:=\\s]+['\"]?([A-Za-z0-9/+=]{40})['\"]?",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 40,
      "maxLength": 40
    },
    {
      "name": "AWS Session Token",
      "regex": "aws_session_token[:=\\s]+['\"]?([A-Za-z0-9/+=]{200,400})['\"]?",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 100,
      "maxLength": 400
    },
    {
      "name": "Google API Key",
      "regex": "\\bAIza[0-9A-Za-z-_]{35}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 39,
      "maxLength": 39
    },
    {
      "name": "Google OAuth Access Token",
      "regex": "\\bya29\\.[0-9A-Za-z\\-_]+\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 20,
      "maxLength": 100
    },
    {
      "name": "Google Recaptcha Key",
      "regex": "(?:=|['\"])?(6L[0-9A-Za-z]{39})(?:=|['\"])?",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 40,
      "maxLength": 40
    },
    {
      "name": "Firebase API Key",
      "regex": "\\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 150,
      "maxLength": 200
    },
    {
      "name": "OpenAI API Key",
      "regex": "\\bsk-[a-zA-Z0-9]{48}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 51,
      "maxLength": 51
    },
    {
      "name": "OpenAI Organization Key",
      "regex": "\\borg-[a-zA-Z0-9]{20,30}\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 23,
      "maxLength": 33
    },
    {
      "name": "GitHub Personal Access Token",
      "regex": "\\bghp_[a-zA-Z0-9]{36,255}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 39,
      "maxLength": 259
    },
    {
      "name": "GitHub OAuth Token",
      "regex": "\\bgho_[a-zA-Z0-9]{36,255}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 39,
      "maxLength": 259
    },
    {
      "name": "GitHub App Token",
      "regex": "\\bghu_[a-zA-Z0-9]{36,255}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 39,
      "maxLength": 259
    },
    {
      "name": "GitHub Refresh Token",
      "regex": "\\bghr_[a-zA-Z0-9]{36,255}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 39,
      "maxLength": 259
    },
    {
      "name": "GitHub App Installation Token",
      "regex": "\\bghs_[a-zA-Z0-9]{36,255}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 40,
      "maxLength": 259
    },
    {
      "name": "GitHub Fine-Grained PAT",
      "regex": "\\bgithub_pat_[a-zA-Z0-9_]{20,255}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 31,
      "maxLength": 266
    },
    {
      "name": "GitLab Personal Access Token",
      "regex": "\\bglpat-[a-zA-Z0-9\\-_]{20,}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 26,
      "maxLength": 160
    },
    {
      "name": "GitLab OAuth Secret",
      "regex": "\\bgloas-[a-zA-Z0-9\\-_]{20,}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 26,
      "maxLength": 160
    },
    {
      "name": "GitLab Deploy Token",
      "regex": "\\bgldt-[a-zA-Z0-9\\-_]{20,}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 25,
      "maxLength": 160
    },
    {
      "name": "GitLab Runner Auth Token",
      "regex": "\\bglrtr?-[a-zA-Z0-9\\-_]{20,}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 25,
      "maxLength": 160
    },
    {
      "name": "GitLab CI/CD Job Token",
      "regex": "\\bglcbt-[a-zA-Z0-9\\-_]{20,}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 26,
      "maxLength": 160
    },
    {
      "name": "GitLab Trigger Token",
      "regex": "\\bglptt-[a-zA-Z0-9\\-_]{20,}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 26,
      "maxLength": 160
    },
    {
      "name": "GitLab Feed Token",
      "regex": "\\bglft-[a-zA-Z0-9\\-_]{20,}\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 25,
      "maxLength": 160
    },
    {
      "name": "GitLab Incoming Mail Token",
      "regex": "\\bglimt-[a-zA-Z0-9\\-_]{20,}\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 26,
      "maxLength": 160
    },
    {
      "name": "GitLab Agent Token",
      "regex": "\\bglagent-[a-zA-Z0-9\\-_]{20,}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 28,
      "maxLength": 160
    },
    {
      "name": "GitLab SCIM Token",
      "regex": "\\bglsoat-[a-zA-Z0-9\\-_]{20,}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 27,
      "maxLength": 160
    },
    {
      "name": "GitLab Feature Flag Token",
      "regex": "\\bglffct-[a-zA-Z0-9\\-_]{20,}\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 27,
      "maxLength": 160
    },
    {
      "name": "GitLab Session Cookie",
      "regex": "_gitlab_session=[a-zA-Z0-9%._\\-]{20,}",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 35,
      "maxLength": 300
    },
    {
      "name": "GitLab Workspace Token",
      "regex": "\\bglwt-[a-zA-Z0-9\\-_]{20,}\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 25,
      "maxLength": 160
    },
    {
      "name": "GitHub Client ID",
      "regex": "github_client_id[:=\\s]+['\"]?([a-zA-Z0-9]{20})['\"]?",
      "flags": "gi",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "minLength": 20,
      "maxLength": 20
    },
    {
      "name": "GitHub Client Secret",
      "regex": "github_client_secret[:=\\s]+['\"]?([a-zA-Z0-9]{40})['\"]?",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 40,
      "maxLength": 40
    },
    {
      "name": "AWS STS Access Key ID",
      "regex": "\\bASIA[0-9A-Z]{16}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 20,
      "maxLength": 20
    },
    {
      "name": "Azure API Key",
      "regex": "x-api-key:\\s*([a-zA-Z0-9-_]{32,})",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 32,
      "maxLength": 64
    },
    {
      "name": "Azure Subscription Key",
      "regex": "azure_subscription_key[:=\\s]+['\"]?([a-zA-Z0-9]{32})['\"]?",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 32,
      "maxLength": 32
    },
    {
      "name": "Azure Storage Account Key",
      "regex": "accountkey[:=\\s]+['\"]?([A-Za-z0-9+/]{86,88}={0,2})['\"]?",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 86,
      "maxLength": 90
    },
    {
      "name": "Stripe Secret Key",
      "regex": "\\bsk_live_[0-9a-zA-Z]{24,}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 32,
      "maxLength": 40
    },
    {
      "name": "Stripe Publishable Key",
      "regex": "\\bpk_live_[0-9a-zA-Z]{24,}\\b",
      "flags": "g",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "minLength": 32,
      "maxLength": 40
    },
    {
      "name": "Stripe Restricted Key",
      "regex": "\\brk_live_[0-9a-zA-Z]{24,}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 32,
      "maxLength": 40
    },
    {
      "name": "Stripe Test Secret Key",
      "regex": "\\bsk_test_[0-9a-zA-Z]{24,}\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 32,
      "maxLength": 100
    },
    {
      "name": "Stripe Test Restricted Key",
      "regex": "\\brk_test_[0-9a-zA-Z]{24,}\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 32,
      "maxLength": 100
    },
    {
      "name": "Twilio Account SID",
      "regex": "\\bAC[a-zA-Z0-9]{32}\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 34,
      "maxLength": 34
    },
    {
      "name": "Twilio Auth Token",
      "regex": "\\b[a-zA-Z0-9]{32}\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "MEDIUM",
      "minLength": 32,
      "maxLength": 32,
      "context": [
        "twilio",
        "auth",
        "token"
      ]
    },
    {
      "name": "Twilio API Key",
      "regex": "\\bSK[a-zA-Z0-9]{32}\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 34,
      "maxLength": 34
    },
    {
      "name": "Slack Bot Token",
      "regex": "\\bxoxb-[a-zA-Z0-9]{10,48}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 14,
      "maxLength": 60
    },
    {
      "name": "Slack User Token",
      "regex": "\\bxoxa-[a-zA-Z0-9]{10,48}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 14,
      "maxLength": 60
    },
    {
      "name": "Slack Workspace Token",
      "regex": "\\bxoxr-[a-zA-Z0-9]{10,48}\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 14,
      "maxLength": 60
    },
    {
      "name": "Slack User Token (xoxp)",
      "regex": "\\bxoxp-[a-zA-Z0-9-]{10,200}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 14,
      "maxLength": 220
    },
    {
      "name": "Slack App-Level Token",
      "regex": "\\bxapp-[0-9A-Za-z-]{20,200}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 25,
      "maxLength": 220
    },
    {
      "name": "Slack Webhook URL",
      "regex": "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+",
      "flags": "g",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "minLength": 40,
      "maxLength": 100
    },
    {
      "name": "SendGrid API Key",
      "regex": "\\bSG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 69,
      "maxLength": 69
    },
    {
      "name": "Mailgun API Key",
      "regex": "\\bkey-[a-zA-Z0-9]{32}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 36,
      "maxLength": 36
    },
    {
      "name": "Brevo/Sendinblue API Key",
      "regex": "\\bxkeysib-[a-zA-Z0-9\\-_]{32,}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 40,
      "maxLength": 200
    },
    {
      "name": "Google OAuth Client Secret",
      "regex": "\\bGOCSPX-[a-zA-Z0-9\\-_]{20,}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 27,
      "maxLength": 120
    },
    {
      "name": "MongoDB Connection String",
      "regex": "mongodb(\\+srv)?://[^\\s\"']+",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 20,
      "maxLength": 200
    },
    {
      "name": "MySQL Connection String",
      "regex": "mysql://[^\\s\"']+",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 20,
      "maxLength": 200
    },
    {
      "name": "PostgreSQL Connection String",
      "regex": "postgres(ql)?://[^\\s\"']+",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 20,
      "maxLength": 200
    },
    {
      "name": "SQL Server Connection String",
      "regex": "sqlserver://[^\\s\"']+",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 20,
      "maxLength": 240
    },
    {
      "name": "AMQP Connection String",
      "regex": "amqps?://[^\\s\"']+",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 20,
      "maxLength": 240
    },
    {
      "name": "Redis Connection String",
      "regex": "redis://[^\\s\"']+",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 15,
      "maxLength": 200
    },
    {
      "name": "SSH Private Key (RSA)",
      "regex": "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 100,
      "maxLength": 5000
    },
    {
      "name": "SSH Private Key (OpenSSH)",
      "regex": "-----BEGIN OPENSSH PRIVATE KEY-----",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 100,
      "maxLength": 5000
    },
    {
      "name": "PGP Private Key",
      "regex": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 100,
      "maxLength": 5000
    },
    {
      "name": "JWT Token",
      "regex": "\\beyJ[a-zA-Z0-9-_]+\\.[a-zA-Z0-9-_]+\\.[a-zA-Z0-9-_]+\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 50,
      "maxLength": 500
    },
    {
      "name": "OpenAI Project API Key",
      "regex": "\\bsk-proj-[a-zA-Z0-9\\-_]{20,200}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 28,
      "maxLength": 208
    },
    {
      "name": "OpenAI Service Account Key",
      "regex": "\\bsk-svcacct-[a-zA-Z0-9\\-_]{20,200}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 31,
      "maxLength": 211
    },
    {
      "name": "Anthropic API Key",
      "regex": "\\bsk-ant-(?:api\\d{2}-)?[a-zA-Z0-9\\-_]{20,200}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 27,
      "maxLength": 220
    },
    {
      "name": "Hugging Face Access Token",
      "regex": "\\bhf_[a-zA-Z0-9]{30,}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 33,
      "maxLength": 120
    },
    {
      "name": "PyPI API Token",
      "regex": "\\bpypi-[A-Za-z0-9\\-_]{60,120}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 65,
      "maxLength": 130
    },
    {
      "name": "NPM Granular Token",
      "regex": "\\bnpm_[a-zA-Z0-9]{36}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 40,
      "maxLength": 40
    },
    {
      "name": "Linear API Key",
      "regex": "\\blin_api_[a-zA-Z0-9]{20,}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 28,
      "maxLength": 120
    },
    {
      "name": "Linear OAuth Token",
      "regex": "\\blin_oauth_[a-zA-Z0-9]{20,}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 30,
      "maxLength": 120
    },
    {
      "name": "Facebook Access Token",
      "regex": "\\bEAACEdEose0cBA[a-zA-Z0-9]+\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 30,
      "maxLength": 200
    },
    {
      "name": "PayPal Client ID",
      "regex": "paypal_client_id[:=\\s]+['\"]?([a-zA-Z0-9]{20,})['\"]?",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 20,
      "maxLength": 50
    },
    {
      "name": "PayPal Secret",
      "regex": "paypal_secret[:=\\s]+['\"]?([a-zA-Z0-9]{32})['\"]?",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 32,
      "maxLength": 32
    },
    {
      "name": "Square OAuth Secret",
      "regex": "\\bsq0csp-[a-zA-Z0-9\\-_]{43}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 46,
      "maxLength": 48
    },
    {
      "name": "Square Access Token",
      "regex": "\\bsq0atp-[a-zA-Z0-9\\-_]{22}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 26,
      "maxLength": 26
    },
    {
      "name": "Shopify Access Token",
      "regex": "\\bshpat_[a-fA-F0-9]{32}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 36,
      "maxLength": 36
    },
    {
      "name": "Shopify Storefront Token",
      "regex": "\\bshpss_[a-fA-F0-9]{32}\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 38,
      "maxLength": 38
    },
    {
      "name": "Twilio Account SID Full",
      "regex": "twilio_account_sid[:=\\s]+['\"]?([A-Z]{2}[a-zA-Z0-9]{32})['\"]?",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 34,
      "maxLength": 34
    },
    {
      "name": "Twilio Auth Token Full",
      "regex": "twilio_auth_token[:=\\s]+['\"]?([a-zA-Z0-9]{32})['\"]?",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 32,
      "maxLength": 32
    },
    {
      "name": "Algolia API Key",
      "regex": "x-algolia-api-key:\\s*([a-zA-Z0-9]{32})",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 32,
      "maxLength": 32
    },
    {
      "name": "Algolia App ID",
      "regex": "x-algolia-application-id:\\s*([a-zA-Z0-9]{8,10})",
      "flags": "gi",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "minLength": 8,
      "maxLength": 10
    },
    {
      "name": "Heroku API Key",
      "regex": "heroku[_-]?api[_-]?key[:=\\s]+['\"]?([a-fA-F0-9]{32})['\"]?",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 32,
      "maxLength": 32
    },
    {
      "name": "Discord Bot Token",
      "regex": "[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_-]{27,}",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 40,
      "maxLength": 80
    },
    {
      "name": "Telegram Bot Token",
      "regex": "\\b\\d{8,10}:[a-zA-Z0-9_-]{35}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 45,
      "maxLength": 50
    },
    {
      "name": "NPM Token",
      "regex": "npm[_-]?token[:=\\s]+['\"]?([a-f0-9-]{36})['\"]?",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 36,
      "maxLength": 36
    },
    {
      "name": "Private Key Data",
      "regex": "private[_-]?key[:=\\s]+['\"]?([a-zA-Z0-9+/=]{50,})['\"]?",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 50,
      "maxLength": 5000
    },
    {
      "name": "Environment Secret Variable",
      "regex": "(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)[_-]?(name|var)?[:=\\s]+['\"]?([a-zA-Z0-9_\\-]{20,})['\"]?",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "MEDIUM",
      "minLength": 20,
      "maxLength": 100
    },
    {
      "name": "Bearer Token",
      "regex": "bearer\\s+[a-zA-Z0-9\\-._~+/]+=*",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "MEDIUM",
      "minLength": 20,
      "maxLength": 200
    },
    {
      "name": "Generic API Key Assignment",
      "regex": "(api[_-]?key|apikey|secret[_-]?key|client[_-]?secret)[:=\\s]+['\"]([a-zA-Z0-9_\\-]{16,64})['\"]",
      "flags": "gi",
      "severity": "MEDIUM",
      "confidence": "LOW",
      "minLength": 16,
      "maxLength": 64,
      "context": [
        "api",
        "key",
        "secret"
      ]
    },
    {
      "name": "Generic Token Assignment",
      "regex": "(access[_-]?token|auth[_-]?token|token)[=:]\\s*['\"]([a-zA-Z0-9_\\-]{20,})['\"]",
      "flags": "gi",
      "severity": "MEDIUM",
      "confidence": "LOW",
      "minLength": 20,
      "maxLength": 100
    },
    {
      "name": "Password in Config",
      "regex": "(password|passwd|pwd|secret)[:=\\s]+['\"]([^'\"]{8,})['\"]",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "MEDIUM",
      "minLength": 8,
      "maxLength": 100
    },
    {
      "name": "Database Password",
      "regex": "(db[_-]?password|database[_-]?password|mysql[_-]?password|postgres[_-]?password)[:=\\s]+['\"]?([a-zA-Z0-9!@#$%^\u0026*()_+\\-={}:;,.?\u003c\u003e~\\x60|\\\\]{6,})['\"]?",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 6,
      "maxLength": 100
    },
    {
      "name": "Email Password Combo",
      "regex": "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}:[^\\s'\"]{6,}",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 20,
      "maxLength": 100
    },
    {
      "name": "Private IP Address",
      "regex": "\\b(?:10\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])|192\\.168)\\.\\d{1,3}\\.\\d{1,3}\\b",
      "flags": "g",
      "severity": "LOW",
      "confidence": "HIGH",
      "minLength": 7,
      "maxLength": 15
    },
    {
      "name": "Credit Card Number",
      "regex": "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 13,
      "maxLength": 19
    },
    {
      "name": "SSN",
      "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 11,
      "maxLength": 11
    },
    {
      "name": "Ethereum Private Key",
      "regex": "\\b[a-fA-F0-9]{64}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "MEDIUM",
      "minLength": 64,
      "maxLength": 64
    },
    {
      "name": "Authorization Header",
      "regex": "authorization:\\s*(bearer|token|basic)\\s+[a-zA-Z0-9\\-._~+/]+=*",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 20,
      "maxLength": 200
    },
    {
      "name": "API Key in URL",
      "regex": "[?\u0026](api[_-]?key|apikey|key|token|access[_-]?token)=[a-zA-Z0-9_\\-]{16,}",
      "flags": "g",
      "severity": "MEDIUM",
      "confidence": "MEDIUM",
      "minLength": 20,
      "maxLength": 100
    },
    {
      "name": "Client ID Assignment",
      "regex": "(client[_-]?id|cid)[:=\\s]+['\"]?([a-zA-Z0-9_\\-]{10,})['\"]?",
      "flags": "gi",
      "severity": "MEDIUM",
      "confidence": "MEDIUM",
      "minLength": 10,
      "maxLength": 50
    },
    {
      "name": "Client Secret Assignment",
      "regex": "(client[_-]?secret|csecret)[:=\\s]+['\"]?([a-zA-Z0-9_\\-]{16,})['\"]?",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 16,
      "maxLength": 64
    },
    {
      "name": "Dropbox Access Token",
      "regex": "\\bsl\\.[a-zA-Z0-9_-]{15,}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 20,
      "maxLength": 50
    },
    {
      "name": "Mailchimp API Key",
      "regex": "[a-f0-9]{32}-us[0-9]{1,2}",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 36,
      "maxLength": 38
    },
    {
      "name": "Contentful Space ID",
      "regex": "[a-zA-Z0-9]{36}",
      "flags": "g",
      "severity": "MEDIUM",
      "confidence": "MEDIUM",
      "minLength": 36,
      "maxLength": 36
    },
    {
      "name": "Contentful Access Token",
      "regex": "access_token=([a-zA-Z0-9]{32,64})",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 32,
      "maxLength": 64
    },
    {
      "name": "HubSpot API Key",
      "regex": "hapikey=[a-zA-Z0-9]{32}",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 38,
      "maxLength": 38
    },
    {
      "name": "Twitter API Key",
      "regex": "twitter_api_key[:=\\s]+['\"]?([a-zA-Z0-9]{25,})['\"]?",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 25,
      "maxLength": 35
    },
    {
      "name": "Twitter API Secret",
      "regex": "twitter_api_secret[:=\\s]+['\"]?([a-zA-Z0-9]{35,})['\"]?",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 35,
      "maxLength": 50
    },
    {
      "name": "Twitter Bearer Token",
      "regex": "twitter_bearer_token[:=\\s]+['\"]?([a-zA-Z0-9]{60,})['\"]?",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 60,
      "maxLength": 100
    },
    {
      "name": "Misc Secret Pattern 1",
      "regex": "secret[_-]?(key|token)?[:=\\s]+['\"]?([a-zA-Z0-9_\\-]{20,})['\"]?",
      "flags": "gi",
      "severity": "MEDIUM",
      "confidence": "LOW",
      "minLength": 20,
      "maxLength": 100
    },
    {
      "name": "Misc Secret Pattern 2",
      "regex": "access[_-]?key[:=\\s]+['\"]?([a-zA-Z0-9_\\-]{16,})['\"]?",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "MEDIUM",
      "minLength": 16,
      "maxLength": 50
    },
    {
      "name": "Misc Token Pattern",
      "regex": "token[_-]?(key|secret)?[:=\\s]+['\"]?([a-zA-Z0-9_\\-]{20,})['\"]?",
      "flags": "gi",
      "severity": "MEDIUM",
      "confidence": "LOW",
      "minLength": 20,
      "maxLength": 100
    },
    {
      "name": "Cloudflare API Key",
      "regex": "cloudflare[_-]?api[_-]?key[:=\\s]+['\"]?([a-fA-F0-9]{37})['\"]?",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 37,
      "maxLength": 37
    },
    {
      "name": "DigitalOcean Token",
      "regex": "digitalocean[_-]?token[:=\\s]+['\"]?([a-zA-Z0-9]{64})['\"]?",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 64,
      "maxLength": 64
    },
    {
      "name": "Linode API Token",
      "regex": "linode[_-]?api[_-]?token[:=\\s]+['\"]?([a-zA-Z0-9]{64})['\"]?",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 64,
      "maxLength": 64
    },
    {
      "name": "Datadog API Key",
      "regex": "datadog[_-]?api[_-]?key[:=\\s]+['\"]?([a-zA-Z0-9]{32})['\"]?",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 32,
      "maxLength": 32
    },
    {
      "name": "CircleCI Token",
      "regex": "circleci[_-]?token[:=\\s]+['\"]?([a-zA-Z0-9]{20,})['\"]?",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 20,
      "maxLength": 40
    },
    {
      "name": "Travis CI Token",
      "regex": "travis[_-]?token[:=\\s]+['\"]?([a-zA-Z0-9]{40})['\"]?",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 40,
      "maxLength": 40
    },
    {
      "name": "Codecov Token",
      "regex": "codecov[_-]?token[:=\\s]+['\"]?([a-zA-Z0-9]{20,})['\"]?",
      "flags": "gi",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "minLength": 20,
      "maxLength": 50
    },
    {
      "name": "Infura API Key",
      "regex": "https://[a-zA-Z0-9.-]*\\.infura\\.io/v[0-9]+/([a-fA-F0-9]{32})",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 32,
      "maxLength": 60
    },
    {
      "name": "Shodan API Key",
      "regex": "https://api\\.shodan\\.io/.*?key=([a-zA-Z0-9]{32})",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 40,
      "maxLength": 50
    },
    {
      "name": "YouTube API Key",
      "regex": "youtube[_-]?api[_-]?key[:=\\s]+['\"]?(AIza[0-9A-Za-z\\-_]{33})['\"]?",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 39,
      "maxLength": 45
    },
    {
      "name": "Foursquare API Key",
      "regex": "foursquare[_-]?api[_-]?key[:=\\s]+['\"]?(FSQ[a-zA-Z0-9]{32})['\"]?",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 35,
      "maxLength": 40
    },
    {
      "name": "Mixpanel Token",
      "regex": "mixpanel[_-]?token[:=\\s]+['\"]?([a-f0-9]{32})['\"]?",
      "flags": "gi",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "minLength": 32,
      "maxLength": 32
    },
    {
      "name": "Pusher Credentials",
      "regex": "(pusher[_-]?(app[_-]?(id|key|secret)|channel|cluster))[=:]\\s*['\"]?([a-zA-Z0-9]{10,})['\"]?",
      "flags": "gi",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "minLength": 10,
      "maxLength": 100
    },
    {
      "name": "Microsoft Teams Webhook",
      "regex": "https://[a-zA-Z0-9.-]+\\.webhook\\.office\\.com/webhookb2/[a-zA-Z0-9-]+@[a-zA-Z0-9-]+/IncomingWebhook/[a-zA-Z0-9-]+/[a-zA-Z0-9-]+",
      "flags": "g",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "minLength": 50,
      "maxLength": 150
    },
    {
      "name": "Discord Webhook",
      "regex": "https://discord(app)?\\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+",
      "flags": "g",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "minLength": 40,
      "maxLength": 100
    },
    {
      "name": "Base64 Encoded Secret",
      "regex": "(password|secret|token|key)[_-]?(base64)?[_-]?(encoded)?[:=\\s]+['\"]?([A-Za-z0-9+/]{20,}={0,2})['\"]?",
      "flags": "gi",
      "severity": "MEDIUM",
      "confidence": "LOW",
      "minLength": 20,
      "maxLength": 200
    },
    {
      "name": "Hex Encoded Secret",
      "regex": "(password|secret|token|key)[_-]?(hex)?[_-]?(encoded)?[:=\\s]+['\"]?([a-fA-F0-9]{20,})['\"]?",
      "flags": "gi",
      "severity": "MEDIUM",
      "confidence": "LOW",
      "minLength": 20,
      "maxLength": 200
    },
    {
      "name": "PGP Public Key",
      "regex": "-----BEGIN PGP PUBLIC KEY BLOCK-----",
      "flags": "g",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "minLength": 50,
      "maxLength": 5000
    },
    {
      "name": "PGP Private Key",
      "regex": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 50,
      "maxLength": 5000
    },
    {
      "name": "PEM Certificate",
      "regex": "-----BEGIN CERTIFICATE-----",
      "flags": "g",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "minLength": 50,
      "maxLength": 5000
    },
    {
      "name": "AWS Access Key ID (Alt Prefixes)",
      "regex": "\\b(?:A3T[A-Z0-9]|ABIA|ACCA)[A-Z2-7]{16}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 20,
      "maxLength": 20
    },
    {
      "name": "AWS Bedrock API Key",
      "regex": "\\bABSK[A-Za-z0-9+/]{109,269}={0,2}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 113,
      "maxLength": 275
    },
    {
      "name": "Alibaba Cloud Access Key ID",
      "regex": "\\bLTAI[a-zA-Z0-9]{20}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 24,
      "maxLength": 24
    },
    {
      "name": "Azure AD Client Secret",
      "regex": "(?:^|[^A-Za-z0-9_~.])([A-Za-z0-9_~.]{3}\\dQ~[A-Za-z0-9_~.-]{31,34})(?:$|[^A-Za-z0-9_~.-])",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 37,
      "maxLength": 40
    },
    {
      "name": "1Password Secret Key",
      "regex": "\\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 40,
      "maxLength": 45
    },
    {
      "name": "1Password Service Account Token",
      "regex": "\\bops_eyJ[a-zA-Z0-9+/]{250,}={0,3}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 257,
      "maxLength": 5000
    },
    {
      "name": "Age Secret Key",
      "regex": "\\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 60,
      "maxLength": 80
    },
    {
      "name": "Atlassian API Token (ATATT3)",
      "regex": "\\bATATT3[A-Za-z0-9_\\-=]{186}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 192,
      "maxLength": 192
    },
    {
      "name": "Artifactory API Key",
      "regex": "\\bAKCp[A-Za-z0-9]{69}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 73,
      "maxLength": 73
    },
    {
      "name": "Artifactory Reference Token",
      "regex": "\\bcmVmd[A-Za-z0-9]{59}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 64,
      "maxLength": 64
    },
    {
      "name": "Airtable Personal Access Token",
      "regex": "\\bpat[A-Za-z0-9]{14}\\.[A-Fa-f0-9]{64}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 82,
      "maxLength": 82
    },
    {
      "name": "Bitbucket Client ID",
      "regex": "bitbucket[_-]?(client[_-]?id|id)[:=\\s]+['\"]?([a-zA-Z0-9]{32})['\"]?",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 32,
      "maxLength": 32
    },
    {
      "name": "Bitbucket Client Secret",
      "regex": "bitbucket[_-]?(client[_-]?secret|secret)[:=\\s]+['\"]?([a-zA-Z0-9_\\-=]{64})['\"]?",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 64,
      "maxLength": 64
    },
    {
      "name": "Cloudflare Origin CA Key",
      "regex": "\\bv1\\.0-[a-f0-9]{24}-[a-f0-9]{146}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 176,
      "maxLength": 176
    },
    {
      "name": "Databricks API Token",
      "regex": "\\bdapi[a-f0-9]{32}(?:-\\d)?\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 36,
      "maxLength": 38
    },
    {
      "name": "DigitalOcean OAuth Access Token",
      "regex": "\\bdoo_v1_[a-f0-9]{64}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 71,
      "maxLength": 71
    },
    {
      "name": "DigitalOcean PAT (dop_v1)",
      "regex": "\\bdop_v1_[a-f0-9]{64}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 71,
      "maxLength": 71
    },
    {
      "name": "DigitalOcean Refresh Token",
      "regex": "\\bdor_v1_[a-f0-9]{64}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 71,
      "maxLength": 71
    },
    {
      "name": "Docker Hub PAT",
      "regex": "\\bdckr_pat_[a-zA-Z0-9_-]{27}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 36,
      "maxLength": 36
    },
    {
      "name": "Docker Hub OAT",
      "regex": "\\bdckr_oat_[a-zA-Z0-9_-]{32}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 41,
      "maxLength": 41
    },
    {
      "name": "Doppler Service Token",
      "regex": "\\bdp\\.pt\\.[a-zA-Z0-9]{43}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 49,
      "maxLength": 49
    },
    {
      "name": "Dynatrace API Token",
      "regex": "\\bdt0c01\\.[a-z0-9]{24}\\.[a-z0-9]{64}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 96,
      "maxLength": 96
    },
    {
      "name": "EasyPost API Key",
      "regex": "\\bEZAK[a-zA-Z0-9]{54}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 58,
      "maxLength": 58
    },
    {
      "name": "EasyPost Test API Key",
      "regex": "\\bEZTK[a-zA-Z0-9]{54}\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 58,
      "maxLength": 58
    },
    {
      "name": "Fly.io Access Token (fo1)",
      "regex": "\\bfo1_[A-Za-z0-9_-]{43}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 47,
      "maxLength": 47
    },
    {
      "name": "Fly.io Machine Token (fm1a/fm1r)",
      "regex": "\\bfm1[ar]_[A-Za-z0-9+/]{100,}={0,3}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 105,
      "maxLength": 5000
    },
    {
      "name": "Fly.io Machine Token (fm2)",
      "regex": "\\bfm2_[A-Za-z0-9+/]{100,}={0,3}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 104,
      "maxLength": 5000
    },
    {
      "name": "Frame.io API Token",
      "regex": "\\bfio-u-[a-zA-Z0-9\\-_=]{64}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 70,
      "maxLength": 70
    },
    {
      "name": "Grafana API Key (eyJrIjoi)",
      "regex": "\\beyJrIjoi[A-Za-z0-9]{70,400}={0,3}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 78,
      "maxLength": 410
    },
    {
      "name": "Grafana Cloud API Token",
      "regex": "\\bglc_[A-Za-z0-9+/]{32,400}={0,3}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 36,
      "maxLength": 410
    },
    {
      "name": "Grafana Service Account Token",
      "regex": "\\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 46,
      "maxLength": 46
    },
    {
      "name": "HashiCorp Terraform API Token",
      "regex": "\\b[a-z0-9]{14}\\.atlasv1\\.[a-z0-9\\-_=]{60,70}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 83,
      "maxLength": 93
    },
    {
      "name": "Hugging Face Organization Token",
      "regex": "\\bapi_org_[a-z]{34}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 42,
      "maxLength": 42
    },
    {
      "name": "Infracost API Key",
      "regex": "\\bico-[A-Za-z0-9]{32}\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 36,
      "maxLength": 36
    },
    {
      "name": "Netlify Personal Access Token",
      "regex": "\\bnfp_[a-zA-Z0-9_]{36}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 40,
      "maxLength": 40
    },
    {
      "name": "Notion API Token",
      "regex": "\\bntn_[0-9]{11}[A-Za-z0-9]{35}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 50,
      "maxLength": 50
    },
    {
      "name": "OpenAI Admin API Key",
      "regex": "\\bsk-admin-[A-Za-z0-9_-]{20,200}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 29,
      "maxLength": 209
    },
    {
      "name": "OpenShift Pull Secret Token",
      "regex": "\\bsha256~[A-Za-z0-9_-]{43}\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 50,
      "maxLength": 50
    },
    {
      "name": "Perplexity API Key",
      "regex": "\\bpplx-[A-Za-z0-9]{48}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 53,
      "maxLength": 53
    },
    {
      "name": "PlanetScale API Token",
      "regex": "\\bpscale_tkn_[A-Za-z0-9=._-]{32,64}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 43,
      "maxLength": 75
    },
    {
      "name": "PlanetScale OAuth Token",
      "regex": "\\bpscale_oauth_[A-Za-z0-9=._-]{32,64}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 45,
      "maxLength": 77
    },
    {
      "name": "PlanetScale Password Token",
      "regex": "\\bpscale_pw_[A-Za-z0-9=._-]{32,64}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 42,
      "maxLength": 74
    },
    {
      "name": "Postman API Key",
      "regex": "\\bPMAK-[A-Fa-f0-9]{24}-[A-Fa-f0-9]{34}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 64,
      "maxLength": 64
    },
    {
      "name": "Pulumi API Token",
      "regex": "\\bpul-[a-f0-9]{40}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 44,
      "maxLength": 44
    },
    {
      "name": "ReadMe API Key",
      "regex": "\\brdme_[a-z0-9]{70}\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 75,
      "maxLength": 75
    },
    {
      "name": "RubyGems API Key",
      "regex": "\\brubygems_[a-f0-9]{48}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 57,
      "maxLength": 57
    },
    {
      "name": "Sentry Auth Token",
      "regex": "\\bsntrys_eyJpYXQiO[A-Za-z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[A-Za-z0-9+/]{10,200}={0,2}_[A-Za-z0-9+/]{43}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 80,
      "maxLength": 600
    },
    {
      "name": "Sentry User Token",
      "regex": "\\bsntryu_[a-f0-9]{64}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 71,
      "maxLength": 71
    },
    {
      "name": "Slack Configuration Access Token",
      "regex": "\\bxoxe\\.xox[bp]-\\d-[A-Z0-9]{163,166}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 174,
      "maxLength": 178
    },
    {
      "name": "Slack Configuration Refresh Token",
      "regex": "\\bxoxe-\\d-[A-Z0-9]{146}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 153,
      "maxLength": 153
    },
    {
      "name": "Slack Legacy Token (xoxs/xoxo)",
      "regex": "\\bxox[os]-\\d+-\\d+-\\d+-[a-fA-F0-9]{10,64}\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 24,
      "maxLength": 100
    },
    {
      "name": "Sourcegraph Access Token",
      "regex": "\\bsgp_(?:[A-Fa-f0-9]{16}|local)_[A-Fa-f0-9]{40}\\b|\\bsgp_[A-Fa-f0-9]{40}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 44,
      "maxLength": 60
    },
    {
      "name": "Stripe Webhook Signing Secret",
      "regex": "\\bwhsec_[A-Za-z0-9]{16,200}\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 22,
      "maxLength": 206
    },
    {
      "name": "GitLab PAT (v2)",
      "regex": "\\bglpat-[0-9A-Za-z_-]{27,300}\\.[0-9a-z]{9}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 43,
      "maxLength": 320
    },
    {
      "name": "GitLab Runner Token (glrt)",
      "regex": "\\bglrt-[0-9A-Za-z_\\-]{20,}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 25,
      "maxLength": 320
    },
    {
      "name": "GitLab Runner Token (glrt-t)",
      "regex": "\\bglrt-t\\d_[0-9A-Za-z_\\-]{27,300}\\.[0-9a-z]{9}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 46,
      "maxLength": 330
    },
    {
      "name": "New Relic Browser API Key",
      "regex": "\\bNRJS-[a-f0-9]{19}\\b",
      "flags": "g",
      "severity": "HIGH",
      "confidence": "HIGH",
      "minLength": 24,
      "maxLength": 24
    },
    {
      "name": "New Relic Insert Key",
      "regex": "\\bNRII-[a-z0-9-]{32}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 37,
      "maxLength": 37
    },
    {
      "name": "New Relic User API Key",
      "regex": "\\bNRAK-[a-z0-9]{27}\\b",
      "flags": "g",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "minLength": 32,
      "maxLength": 32
    },
    {
      "name": "JavaScript eval() Usage",
      "regex": "\\beval\\s*\\(",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "category": "Code Vulnerability",
      "cwe": "CWE-95",
      "description": "Dynamic code execution via eval can lead to code injection."
    },
    {
      "name": "Function Constructor Usage",
      "regex": "\\bnew\\s+Function\\s*\\(",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "category": "Code Vulnerability",
      "cwe": "CWE-95",
      "description": "Function constructor dynamically executes strings as code."
    },
    {
      "name": "setTimeout/setInterval String Execution",
      "regex": "\\bset(?:Timeout|Interval)\\s*\\(\\s*['\"`]",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "category": "Code Vulnerability",
      "cwe": "CWE-95",
      "description": "String-based timer callbacks execute as code and are injection-prone."
    },
    {
      "name": "React dangerouslySetInnerHTML",
      "regex": "dangerouslySetInnerHTML\\s*=\\s*\\{\\s*\\{\\s*__html\\s*:",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "category": "Code Vulnerability",
      "cwe": "CWE-79",
      "description": "Raw HTML rendering can introduce XSS if unsanitized input is used."
    },
    {
      "name": "DOM innerHTML/outerHTML Assignment",
      "regex": "\\.(?:innerHTML|outerHTML)\\s*=",
      "flags": "gi",
      "severity": "MEDIUM",
      "confidence": "MEDIUM",
      "category": "Code Vulnerability",
      "cwe": "CWE-79",
      "description": "Direct HTML assignment can create DOM-based XSS sinks."
    },
    {
      "name": "document.write Usage",
      "regex": "\\bdocument\\.write\\s*\\(",
      "flags": "gi",
      "severity": "MEDIUM",
      "confidence": "MEDIUM",
      "category": "Code Vulnerability",
      "cwe": "CWE-79",
      "description": "document.write with untrusted data can inject executable content."
    },
    {
      "name": "Command Execution with Request Input",
      "regex": "\\b(?:exec|execSync|spawn|spawnSync)\\s*\\([^)]*req\\.(?:body|query|params)",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "category": "Code Vulnerability",
      "cwe": "CWE-78",
      "description": "User input passed to command execution APIs may enable command injection."
    },
    {
      "name": "SQL Query String Concatenation",
      "regex": "\\b(?:db|pool|client|connection)\\.(?:query|execute|raw)\\s*\\([^)]*\\+",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "MEDIUM",
      "category": "Code Vulnerability",
      "cwe": "CWE-89",
      "description": "String-built SQL queries are vulnerable to SQL injection."
    },
    {
      "name": "SQL with Direct req Input",
      "regex": "\\b(?:SELECT|INSERT|UPDATE|DELETE)\\b[^;\\n]*\\+\\s*req\\.(?:body|query|params)",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "category": "Code Vulnerability",
      "cwe": "CWE-89",
      "description": "SQL statements concatenated with request data are injection-prone."
    },
    {
      "name": "MongoDB $where Usage",
      "regex": "\\$where\\s*:",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "category": "Code Vulnerability",
      "cwe": "CWE-943",
      "description": "MongoDB $where executes JavaScript and can enable NoSQL injection."
    },
    {
      "name": "Mongoose Query with req Object",
      "regex": "\\b(?:find|findOne|updateOne|updateMany|deleteOne|deleteMany)\\s*\\(\\s*req\\.(?:body|query|params)",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "MEDIUM",
      "category": "Code Vulnerability",
      "cwe": "CWE-943",
      "description": "Passing request objects directly into queries can allow NoSQL operator injection."
    },
    {
      "name": "Path Traversal via fs and req Input",
      "regex": "\\bfs\\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream)\\s*\\([^)]*req\\.(?:body|query|params)",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "category": "Code Vulnerability",
      "cwe": "CWE-22",
      "description": "Filesystem access with user-controlled paths may permit traversal."
    },
    {
      "name": "Open Redirect with Request Input",
      "regex": "\\bres\\.redirect\\s*\\(\\s*req\\.(?:body|query|params)",
      "flags": "gi",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "category": "Code Vulnerability",
      "cwe": "CWE-601",
      "description": "Redirect targets controlled by request input can cause open redirect issues."
    },
    {
      "name": "SSRF Risk: Outbound Request from req Input",
      "regex": "\\b(?:fetch|axios\\.(?:get|post|request)|http\\.get|https\\.get)\\s*\\(\\s*req\\.(?:body|query|params)",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "MEDIUM",
      "category": "Code Vulnerability",
      "cwe": "CWE-918",
      "description": "User-controlled URLs used in outbound requests can trigger SSRF."
    },
    {
      "name": "JWT Hardcoded Secret",
      "regex": "\\bjwt\\.sign\\s*\\([^,]+,\\s*['\"][^'\"]{8,}['\"]",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "category": "Code Vulnerability",
      "cwe": "CWE-798",
      "description": "Hardcoded JWT signing secret weakens key rotation and secret hygiene."
    },
    {
      "name": "Weak Hash Algorithm (MD5/SHA1)",
      "regex": "\\bcrypto\\.createHash\\s*\\(\\s*['\"](md5|sha1)['\"]\\s*\\)",
      "flags": "gi",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "category": "Code Vulnerability",
      "cwe": "CWE-327",
      "description": "MD5/SHA1 are cryptographically weak for security-sensitive uses."
    },
    {
      "name": "Deprecated crypto.createCipher",
      "regex": "\\bcrypto\\.createCipher\\s*\\(",
      "flags": "gi",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "category": "Code Vulnerability",
      "cwe": "CWE-327",
      "description": "Deprecated crypto APIs may imply weak or legacy cryptographic choices."
    },
    {
      "name": "Insecure Randomness (Math.random)",
      "regex": "\\bMath\\.random\\s*\\(\\s*\\)",
      "flags": "gi",
      "severity": "MEDIUM",
      "confidence": "MEDIUM",
      "category": "Code Vulnerability",
      "cwe": "CWE-338",
      "description": "Math.random is not suitable for security tokens or secrets."
    },
    {
      "name": "Next.js Public Secret Exposure",
      "regex": "\\bNEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|TOKEN|KEY)\\b",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "category": "Code Vulnerability",
      "cwe": "CWE-200",
      "description": "NEXT_PUBLIC_ variables are exposed to browser bundles."
    },
    {
      "name": "Hardcoded NextAuth Secret",
      "regex": "\\bNEXTAUTH_SECRET\\s*[:=]\\s*['\"][^'\"]{8,}['\"]",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "category": "Code Vulnerability",
      "cwe": "CWE-798",
      "description": "Hardcoded NextAuth secret should be sourced from environment variables."
    },
    {
      "name": "Hardcoded Database URL in Code",
      "regex": "\\bDATABASE_URL\\s*[:=]\\s*['\"](postgres(?:ql)?|mysql|mongodb|redis)://[^'\"]+['\"]",
      "flags": "gi",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "category": "Code Vulnerability",
      "cwe": "CWE-798",
      "description": "Database connection strings should not be hardcoded in client/server source code."
    },
    {
      "name": "TLS Certificate Validation Disabled",
      "regex": "\\brejectUnauthorized\\s*:\\s*false\\b",
      "flags": "gi",
      "severity": "HIGH",
      "confidence": "HIGH",
      "category": "Code Vulnerability",
      "cwe": "CWE-295",
      "description": "Disabling certificate validation permits MITM attacks."
    },
    {
      "name": "CORS Wildcard Origin",
      "regex": "\\bcors\\s*\\(\\s*\\{\\s*origin\\s*:\\s*['\"]\\*['\"]",
      "flags": "gi",
      "severity": "MEDIUM",
      "confidence": "MEDIUM",
      "category": "Code Vulnerability",
      "cwe": "CWE-942",
      "description": "Overly broad CORS origin policy can expose APIs to untrusted origins."
    },
    {
      "name": "Express Route Endpoint",
      "regex": "\\bapp\\.(?:get|post|put|patch|delete|all)\\s*\\(\\s*['\"`][^'\"`]+['\"`]",
      "flags": "gi",
      "severity": "LOW",
      "confidence": "LOW",
      "category": "Endpoint Discovery",
      "cwe": "N/A",
      "description": "Route endpoint detected for manual review of auth, validation, and rate limits."
    },
    {
      "name": "Diffie-Hellman Parameters",
      "regex": "-----BEGIN DH PARAMETERS-----",
      "flags": "g",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "minLength": 50,
      "maxLength": 5000
    }
  ],
  "whitelistPatterns": [
    "example",
    "test",
    "placeholder",
    "dummy",
    "mock",
    "fake",
    "your_",
    "your-",
    "xxx",
    "xxx_",
    "xxx-",
    "abc",
    "123",
    "REPLACE",
    "TODO",
    "FIXME",
    "XXX",
    "CHANGE_ME",
    "SET_ME",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "null",
    "undefined",
    "none",
    "empty",
    "noneYet"
  ],
  "contextWhitelist": [
    "documentation",
    "readme",
    "example",
    "sample",
    "test",
    "mock",
    "dummy",
    "placeholder",
    "template",
    "config.example",
    "env.example",
    ".env.sample",
    ".env.template"
  ],
  "disclosurePaths": [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    "/.DS_Store",
    "/config.js",
    "/runtime-config.js",
    "/env.js",
    "/settings.js",
    "/app-config.js",
    "/webpack-stats.json",
    "/manifest.json",
    "/asset-manifest.json",
    "/sitemap.xml",
    "/robots.txt",
    "/swagger.json",
    "/openapi.json",
    "/.well-known/security.txt"
  ]
};
