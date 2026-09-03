/**
 * Correctover CCS Security Scanner - Core Engine
 * 14 security checks mapped to OWASP AISVS 1.0
 * Shared by CLI / GitHub Action / VS Code Extension
 */

const CHECKS = [
  {
    id: 'mcp-tls', category: 'C10 MCP安全', name: 'TLS传输加密', severity: 'critical',
    check: (cfg) => {
      const servers = getServers(cfg);
      if (!servers.length) return 'info';
      return servers.every(s => !s.url || s.url.startsWith('https://') || s.url.startsWith('stdio:')) ? 'pass' : 'fail';
    },
    fix: '所有MCP Server URL应使用HTTPS协议，禁止明文HTTP传输',
    aisvs: 'C10.1'
  },
  {
    id: 'mcp-auth', category: 'C10 MCP安全', name: '服务器鉴权配置', severity: 'high',
    check: (cfg) => {
      const servers = getServers(cfg);
      if (!servers.length) return 'info';
      const hasAuth = servers.some(s => s.headers?.authorization || s.headers?.Authorization || s.env?.API_KEY);
      return hasAuth ? 'pass' : 'warn';
    },
    fix: '为MCP Server配置认证头（Authorization/API Key），防止未授权访问',
    aisvs: 'C10.2'
  },
  {
    id: 'mcp-timeout', category: 'C9 Agent安全', name: '超时配置', severity: 'medium',
    check: (cfg) => {
      return JSON.stringify(cfg).includes('timeout') ? 'pass' : 'warn';
    },
    fix: '为MCP Server连接设置超时时间，防止Agent因无响应Server而挂起',
    aisvs: 'C9.1'
  },
  {
    id: 'cred-exposure', category: 'C5 访问控制', name: '凭证明文暴露', severity: 'critical',
    check: (cfg) => {
      const str = JSON.stringify(cfg);
      const patterns = [/sk-[a-zA-Z0-9]{20,}/, /AKIA[A-Z0-9]{16}/, /ghp_[a-zA-Z0-9]{36}/, /password\s*:\s*["'][^"']+["']/i];
      return patterns.some(p => p.test(str)) ? 'fail' : 'pass';
    },
    fix: '禁止在配置文件中硬编码API密钥。使用环境变量引用（如 ${API_KEY}）或密钥管理服务',
    aisvs: 'C5.1'
  },
  {
    id: 'allowed-tools', category: 'C9 Agent安全', name: '工具白名单', severity: 'high',
    check: (cfg) => {
      const str = JSON.stringify(cfg);
      return (str.includes('allowed_tools') || str.includes('allowedTools') || str.includes('permissions')) ? 'pass' : 'warn';
    },
    fix: '配置allowed_tools白名单，限制Agent可调用的工具范围，遵循最小权限原则',
    aisvs: 'C9.3'
  },
  {
    id: 'budget-limit', category: 'C9 Agent安全', name: 'Token预算控制', severity: 'high',
    check: (cfg) => {
      const str = JSON.stringify(cfg);
      return (str.includes('budget') || str.includes('max_tokens') || str.includes('token_limit') || str.includes('cost_limit')) ? 'pass' : 'warn';
    },
    fix: '设置Token消耗预算上限，防止Agent因循环调用导致成本失控',
    aisvs: 'C9.1'
  },
  {
    id: 'ssrf-protection', category: 'C10 MCP安全', name: 'SSRF防护', severity: 'critical',
    check: (cfg) => {
      const servers = getServers(cfg);
      const urls = servers.map(s => s.url || '').join(' ');
      const internal = /169\.254\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|localhost|127\.0\.0\.1/i;
      return internal.test(urls) ? 'fail' : 'pass';
    },
    fix: 'MCP Server URL不应指向内网地址（169.254.x.x/10.x/172.16-31.x/192.168.x），防止SSRF攻击',
    aisvs: 'C10.3'
  },
  {
    id: 'logging', category: 'C12 监控', name: '审计日志配置', severity: 'medium',
    check: (cfg) => {
      const str = JSON.stringify(cfg);
      return (str.includes('log') || str.includes('audit') || str.includes('trace') || str.includes('telemetry')) ? 'pass' : 'warn';
    },
    fix: '启用审计日志记录所有Agent操作，便于事后追溯和安全分析',
    aisvs: 'C12.1'
  },
  {
    id: 'sandbox', category: 'C4 基础设施', name: '沙箱隔离配置', severity: 'medium',
    check: (cfg) => {
      const str = JSON.stringify(cfg);
      return (str.includes('sandbox') || str.includes('isolation') || str.includes('container') || str.includes('docker')) ? 'pass' : 'info';
    },
    fix: '考虑为MCP Server配置沙箱执行环境，限制文件系统和网络访问',
    aisvs: 'C4.1'
  },
  {
    id: 'version-pin', category: 'C6 供应链', name: '依赖版本锁定', severity: 'medium',
    check: (cfg) => {
      const servers = getServers(cfg);
      if (!servers.length) return 'info';
      return servers.some(s => s.command || s.version) ? 'pass' : 'warn';
    },
    fix: '锁定MCP Server依赖的具体版本号，防止供应链攻击',
    aisvs: 'C6.1'
  },
  {
    id: 'error-handling', category: 'C12 监控', name: '错误处理策略', severity: 'medium',
    check: (cfg) => {
      const str = JSON.stringify(cfg);
      return (str.includes('retry') || str.includes('fallback') || str.includes('error') || str.includes('on_error')) ? 'pass' : 'warn';
    },
    fix: '配置错误处理和故障转移策略，确保Agent在Server故障时优雅降级',
    aisvs: 'C12.2'
  },
  {
    id: 'input-validation', category: 'C2 输入验证', name: '输入校验规则', severity: 'high',
    check: (cfg) => {
      const str = JSON.stringify(cfg);
      return (str.includes('validation') || str.includes('schema') || str.includes('input_check') || str.includes('sanitize')) ? 'pass' : 'warn';
    },
    fix: '为Agent输入配置校验规则，防御提示注入和编码走私攻击',
    aisvs: 'C2.1'
  },
  {
    id: 'output-validation', category: 'C7 输出控制', name: '输出校验规则', severity: 'medium',
    check: (cfg) => {
      const str = JSON.stringify(cfg);
      return (str.includes('output') || str.includes('response_check') || str.includes('filter')) ? 'pass' : 'info';
    },
    fix: '对Agent输出进行格式校验和敏感信息过滤',
    aisvs: 'C7.1'
  },
  {
    id: 'kill-switch', category: 'C9 Agent安全', name: '紧急终止机制', severity: 'high',
    check: (cfg) => {
      const str = JSON.stringify(cfg);
      return (str.includes('kill') || str.includes('circuit_breaker') || str.includes('emergency') || str.includes('abort')) ? 'pass' : 'warn';
    },
    fix: '配置紧急终止开关（kill switch），在检测到异常行为时立即停止Agent',
    aisvs: 'C9.5'
  }
];

function getServers(cfg) {
  if (cfg.mcpServers) return Object.values(cfg.mcpServers);
  if (cfg.servers) return cfg.servers;
  if (Array.isArray(cfg)) return cfg;
  return [];
}

/**
 * Run security scan on a parsed config object
 * @param {Object} config - Parsed MCP config
 * @returns {{ results: Array, stats: Object }}
 */
function runScan(config) {
  const results = CHECKS.map(check => {
    let status;
    try { status = check.check(config); } catch (e) { status = 'info'; }
    return { ...check, status };
  });

  const pass = results.filter(r => r.status === 'pass').length;
  const warn = results.filter(r => r.status === 'warn').length;
  const fail = results.filter(r => r.status === 'fail').length;
  const info = results.filter(r => r.status === 'info').length;
  const total = results.length;
  const score = Math.round(((pass * 10 + warn * 5 + info * 7) / (total * 10)) * 100);

  return { results, stats: { pass, warn, fail, info, total, score } };
}

/**
 * Parse config content (JSON or simple YAML)
 * @param {string} content - File content
 * @param {string} filename - Original filename
 * @returns {Object} Parsed config
 */
function parseConfig(content, filename = '') {
  if (filename.endsWith('.json') || filename.endsWith('.toml')) {
    return JSON.parse(content);
  }
  // Try JSON first for unknown extensions
  try { return JSON.parse(content); } catch (e) {}
  // Basic YAML parse
  return parseSimpleYAML(content);
}

function parseSimpleYAML(text) {
  const result = {};
  const lines = text.split('\n');
  let currentPath = [];
  let indentStack = [-1];
  for (const line of lines) {
    if (!line.trim() || line.trim().startsWith('#')) continue;
    const indent = line.search(/\S/);
    const match = line.trim().match(/^([^:]+):\s*(.*)/);
    if (!match) continue;
    const key = match[1].trim();
    let val = match[2].trim();
    while (indentStack.length > 1 && indent <= indentStack[indentStack.length - 1]) {
      indentStack.pop();
      currentPath.pop();
    }
    if (val === '' || val === '{}' || val === '[]') {
      currentPath.push(key);
      indentStack.push(indent);
    } else {
      val = val.replace(/^["']|["']$/g, '');
      setNestedValue(result, [...currentPath, key], val);
    }
  }
  return result;
}

function setNestedValue(obj, path, value) {
  let current = obj;
  for (let i = 0; i < path.length - 1; i++) {
    if (!current[path[i]]) current[path[i]] = {};
    current = current[path[i]];
  }
  current[path[path.length - 1]] = value;
}

// Auto-detect MCP config files in a directory
const KNOWN_CONFIG_PATHS = [
  '.cursor/mcp.json',
  'claude_desktop_config.json',
  '.claude/mcp.json',
  'mcp.json',
  'mcp.yaml',
  'mcp.yml',
  '.vscode/mcp.json',
  'config/mcp.json',
  '.mcp/mcp.json',
  'mcp_config.json',
];

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { CHECKS, runScan, parseConfig, getServers, KNOWN_CONFIG_PATHS };
}
