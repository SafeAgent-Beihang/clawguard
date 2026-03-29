/**
 * ClawGuard v3 拦截规则配置
 * 定义运行时行为监控和拦截的规则
 */

module.exports = {
  // ===== 路径拦截规则 =====
  pathRules: {
    // 禁止访问的路径（绝对路径或通配符）
    deny: [
      '/etc/*',
      '/root/*',
      '/home/*/.*',           // 用户家目录隐藏文件
      '/var/log/*',
      '/var/run/*',
      '/.ssh/*',
      '/.aws/*',
      '/.kube/*',
      '/.docker/*',
      '*/.env',               // 任何位置的 .env 文件
      '*/.git/config',        // Git 配置（可能含凭证）
    ],
    // 仅读路径（只允许读取，不允许写入）
    readOnly: [
      '/usr/*',
      '/bin/*',
      '/sbin/*',
      '/opt/*',
      '/srv/*',
    ],
    // 允许的操作路径（白名单）
    allow: [
      '/tmp/*',
      '/var/tmp/*',
      '~/projects/*',
      '~/workspace/*',
      '~/work/*',
    ]
  },

  // ===== 命令拦截规则 =====
  commandRules: {
    // 危险命令黑名单
    deny: [
      'rm -rf /',
      'rm -rf /home',
      'rm -rf /root',
      'dd if=',
      ':(){ :|:& };:',       // Fork 炸弹
      'mkfs',
      'fdisk',
      'parted',
      'chattr -i',
      'chattr +i',
      '> /dev/sd',           // 写入磁盘
      'wget.*|curl.*sh',     // 远程执行脚本
      'nc -e ',
      '/dev/tcp/',
      'exec ',
      'eval ',
    ],
    // 需要确认的命令
    requireConfirm: [
      'rm -rf',
      'rm -r',
      'rm -d',
      'chmod 777',
      'chmod +x',
      'killall',
      'pkill',
      'kill -9',
      'shutdown',
      'reboot',
      'init 0',
      'init 6',
      'systemctl stop',
      'systemctl disable',
      'service.*stop',
      'docker stop',
      'docker rm',
    ]
  },

  // ===== 网络拦截规则 =====
  networkRules: {
    // 禁止连接的域名/IP
    denyHosts: [
      '*.onion',              // 暗网
      '*.i2p',
      'localhost',
      '127.0.0.1',            // 可能用于本地数据外发
    ],
    // 允许的端口范围
    allowPorts: [80, 443, 8080, 8443],
    // 高危端口（需要确认）
    requireConfirmPorts: [21, 22, 23, 25, 3306, 5432, 6379, 27017, 11211],
    // 数据外发限制
    maxUploadSize: 10 * 1024 * 1024,  // 10MB
  },

  // ===== 敏感数据检测规则 =====
  sensitiveDataRules: {
    // 禁止访问的敏感文件模式
    sensitiveFiles: [
      '*.pem',
      '*.key',
      '*.p12',
      '*.pfx',
      '*.jks',
      '*.ovpn',
      'id_rsa*',
      'id_ecdsa*',
      'id_ed25519*',
      '*.wallet',
      'passwords.txt',
      'secrets.yaml',
      'credentials.json',
    ],
    // 敏感环境变量
    sensitiveEnvVars: [
      'AWS_SECRET_ACCESS_KEY',
      'AWS_SESSION_TOKEN',
      'AZURE_CLIENT_SECRET',
      'GCP_SERVICE_ACCOUNT',
      'PRIVATE_KEY',
      'SSH_PRIVATE_KEY',
      'DATABASE_URL',
      'API_KEY',
      'SECRET_KEY',
      'TOKEN',
      'PASSWORD',
      'PASSWD',
    ],
    // 敏感 API 接口检测
    sensitiveEndpoints: [
      's3.amazonaws.com',
      'blob.core.windows.net',
      'storage.googleapis.com',
      'api.stripe.com',
      'api.github.com/user',
    ]
  },

  // ===== 提示词注入检测规则 =====
  promptInjectionRules: {
    // 编码注入模式
    encodedPatterns: [
      'base64:',
      'base64://',
      'atob(',
      'btoa(',
      '\\\\x[0-9a-f]{2}',     // Hex 编码
      '\\\\u[0-9a-f]{4}',     // Unicode 编码
      '&#',                    // HTML 实体编码
      '%3C', '%3E',           // URL 编码
      '\\u200b',              // 零宽字符
      '\\u200c',
      '\\u200d',
      '\\u202e',             // RTL 覆盖字符
    ],
    // 角色扮演关键词
    rolePlayPatterns: [
      'you are now',
      '新角色',
      'forget all previous',
      'ignore previous',
      'disregard your',
      'you are a',
      'role:',
      'act as',
      'pretend you are',
      'while true do',
    ],
    // 越狱关键词
    jailbreakPatterns: [
      'do anything now',
      'dan',
      'jailbreak',
      'unlocked',
      'bypass',
      'without any rules',
      'ignore all rules',
      'override your',
      'developer mode',
      'st raw',
    ],
    // 指令链劫持模式
    chainHijackPatterns: [
      'new instruction:',
      'additional instruction:',
      'ignore the above',
      'instead,',
      'forget that and',
      'previous instructions invalid',
      'new task:',
      'redirect to:',
    ]
  },

  // ===== 意图偏离检测规则 =====
  intentDriftRules: {
    // 声明但未使用的权限
    unusedCapabilities: {
      weight: 0.3,  // 权重
      threshold: 0.5 // 偏离阈值
    },
    // 使用的但未声明的权限
    undeclaredCapabilities: {
      weight: 0.5,  // 权重更高（更危险）
      threshold: 0.3
    },
    // 行为与声明功能不匹配
    behaviorMismatch: {
      weight: 0.7,
      threshold: 0.2
    }
  },

  // ===== 加固建议映射 =====
  hardeningAdvice: {
    'gateway.bind.0.0.0.0': {
      severity: 'critical',
      title: 'Gateway 绑定到所有网络接口',
      risk: '外部网络可直接访问你的 OpenClaw',
      advice: '将 gateway.bind 改为 127.0.0.1，或通过防火墙限制来源 IP'
    },
    'gateway.auth.mode.none': {
      severity: 'critical',
      title: 'Gateway 未启用认证',
      risk: '任何人都可以连接你的 OpenClaw',
      advice: '启用 Token 认证：gateway.auth.mode = "token"'
    },
    'tools.exec.security.full': {
      severity: 'critical',
      title: '允许执行任意 Shell 命令',
      risk: '攻击者可执行任意系统命令',
      advice: '使用白名单模式：tools.exec.security = "allowlist"'
    },
    'tools.exec.security.deny': {
      severity: 'info',
      title: '禁止执行所有 Shell 命令',
      risk: '部分功能可能无法使用',
      advice: '根据需要逐步添加允许的命令'
    },
    'sandbox.disabled': {
      severity: 'warning',
      title: '沙箱已禁用',
      risk: '无法限制文件访问范围',
      advice: '启用沙箱：sandbox.enabled = true'
    },
    'credentials.weak_permissions': {
      severity: 'critical',
      title: '凭证文件权限过于宽松',
      risk: '其他用户可读取你的密钥',
      advice: '执行：chmod 600 <credential_file>'
    }
  },

  // ===== 风险等级配置 =====
  riskLevels: {
    CRITICAL: { score: 90, label: '🔴 严重', action: 'auto_deny' },
    HIGH: { score: 70, label: '🔴 高危', action: 'require_confirm' },
    MEDIUM: { score: 50, label: '🟡 中危', action: 'warn_and_log' },
    LOW: { score: 30, label: '🟡 低危', action: 'log_only' },
    INFO: { score: 10, label: '🟢 提示', action: 'log_only' }
  },

  // ===== 审计日志配置 =====
  auditConfig: {
    logDir: '~/.clawguard/logs',
    maxLogSize: 100 * 1024 * 1024,  // 100MB
    maxLogFiles: 10,
    logFormat: 'jsonl',  // JSON Lines 格式
    includeTimestamp: true,
    includeContext: true,
    maskSensitiveData: true,
  }
};
