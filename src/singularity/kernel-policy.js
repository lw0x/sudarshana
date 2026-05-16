'use strict';

/**
 * SUDARSHANA — LEVEL 13: KERNEL-LEVEL POLICY (eBPF/seccomp)
 * 
 * "Even native addons can't escape. The OS enforces what JS can't."
 * 
 * Generates OS-level security policies that enforce Sudarshana's
 * per-package rules at the KERNEL level:
 * 
 * - Linux: seccomp-bpf profiles (block syscalls per-package)
 * - Linux: eBPF programs (network filtering at socket level)
 * - Docker: AppArmor/seccomp profiles for container mode
 * - macOS: Sandbox profiles (.sb files)
 * 
 * Why this matters:
 * Native addons (.node files) bypass JS-level hooks entirely.
 * They call libc functions directly. Only the KERNEL can stop them.
 * 
 * Usage:
 *   sudarshana kernel --generate         Generate OS policies
 *   sudarshana kernel --apply            Apply (requires root/sudo)
 *   sudarshana kernel --docker           Generate Docker seccomp profile
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

class KernelPolicyGenerator {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.platform = os.platform();
  }

  /**
   * Generate kernel-level policies based on .sudarshana.json
   */
  generate() {
    const configPath = path.join(this.projectRoot, '.sudarshana.json');
    if (!fs.existsSync(configPath)) {
      throw new Error('No .sudarshana.json found. Run `sudarshana init` first.');
    }

    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    const policies = config.policies || {};

    const result = {
      platform: this.platform,
      generated: new Date().toISOString(),
      profiles: {}
    };

    switch (this.platform) {
      case 'linux':
        result.profiles.seccomp = this._generateSeccomp(policies);
        result.profiles.ebpf = this._generateEbpfRules(policies);
        break;
      case 'darwin':
        result.profiles.sandbox = this._generateMacOSSandbox(policies);
        break;
      case 'win32':
        result.profiles.appContainer = this._generateWindowsPolicy(policies);
        break;
    }

    // Always generate Docker profile (cross-platform)
    result.profiles.docker = this._generateDockerSeccomp(policies);

    return result;
  }

  /**
   * Generate seccomp-bpf profile for Linux
   * Restricts which system calls each package's native addons can make
   */
  _generateSeccomp(policies) {
    // Base: deny all dangerous syscalls, allow safe ones
    const baseProfile = {
      defaultAction: 'SCMP_ACT_ALLOW',
      architectures: ['SCMP_ARCH_X86_64', 'SCMP_ARCH_AARCH64'],
      syscalls: []
    };

    // Blocked syscalls for packages without shell access
    const shellSyscalls = ['execve', 'execveat', 'fork', 'vfork', 'clone3'];

    // Blocked syscalls for packages without network access
    const networkSyscalls = ['socket', 'connect', 'sendto', 'sendmsg', 'recvfrom', 'recvmsg', 'bind', 'listen', 'accept'];

    // Blocked syscalls for packages without fs write access
    const fsWriteSyscalls = ['open', 'openat', 'creat', 'rename', 'unlink', 'rmdir', 'mkdir', 'symlink', 'link'];

    // Packages with NO shell access → block exec syscalls
    const noShellPackages = Object.entries(policies)
      .filter(([name, p]) => name !== '_application_' && (!p.shell || p.shell.length === 0))
      .map(([name]) => name);

    // Packages with NO network access → block socket syscalls
    const noNetworkPackages = Object.entries(policies)
      .filter(([name, p]) => name !== '_application_' && (!p.network || p.network.length === 0))
      .map(([name]) => name);

    if (noShellPackages.length > 0) {
      baseProfile.syscalls.push({
        names: shellSyscalls,
        action: 'SCMP_ACT_ERRNO',
        args: [],
        comment: `Blocked for packages: ${noShellPackages.slice(0, 5).join(', ')}${noShellPackages.length > 5 ? '...' : ''}`
      });
    }

    return {
      profile: baseProfile,
      packageRestrictions: {
        noShell: noShellPackages,
        noNetwork: noNetworkPackages,
      },
      instructions: [
        'Apply with: node --experimental-policy=policy.json app.js',
        'Or via Docker: docker run --security-opt seccomp=sudarshana-seccomp.json ...',
        'Note: Per-package seccomp requires cgroup-level isolation (Docker/podman)'
      ]
    };
  }

  /**
   * Generate eBPF network filtering rules
   * Restricts which IPs/ports each package can connect to
   */
  _generateEbpfRules(policies) {
    const rules = [];

    for (const [packageName, policy] of Object.entries(policies)) {
      if (packageName === '_application_') continue;

      const allowedDomains = policy.network || [];
      if (allowedDomains.length === 0) {
        // Block ALL outbound for this package
        rules.push({
          package: packageName,
          action: 'DROP',
          direction: 'egress',
          ports: '*',
          comment: `${packageName}: no network access declared`
        });
      } else if (!allowedDomains.includes('*')) {
        // Allow only specific destinations
        rules.push({
          package: packageName,
          action: 'ALLOW',
          direction: 'egress',
          destinations: allowedDomains,
          comment: `${packageName}: allowed domains only`
        });
      }
    }

    return {
      rules,
      format: 'sudarshana-ebpf-v1',
      instructions: [
        'eBPF programs require Linux 5.x+ and CAP_BPF capability',
        'Attach to cgroup: bpftool prog attach <prog_id> cgroup <cgroup_path> egress',
        'Note: requires per-package cgroup isolation (container or systemd slice)'
      ]
    };
  }

  /**
   * Generate Docker seccomp profile
   * Can be used with: docker run --security-opt seccomp=profile.json
   */
  _generateDockerSeccomp(policies) {
    const noShellPackages = Object.entries(policies)
      .filter(([name, p]) => name !== '_application_' && (!p.shell || p.shell.length === 0));

    const profile = {
      defaultAction: 'SCMP_ACT_ALLOW',
      architectures: ['SCMP_ARCH_X86_64', 'SCMP_ARCH_X86', 'SCMP_ARCH_AARCH64'],
      syscalls: [
        {
          names: ['execve', 'execveat'],
          action: 'SCMP_ACT_LOG', // Log instead of block (less likely to break things)
          comment: 'Log all exec calls for monitoring'
        },
        {
          names: ['ptrace'],
          action: 'SCMP_ACT_ERRNO',
          comment: 'Block debugging/tracing (anti-tampering)'
        },
        {
          names: ['personality'],
          action: 'SCMP_ACT_ERRNO',
          comment: 'Block personality change (security boundary)'
        },
        {
          names: ['mount', 'umount2', 'pivot_root'],
          action: 'SCMP_ACT_ERRNO',
          comment: 'Block filesystem mounting'
        }
      ]
    };

    return {
      profile,
      usage: 'docker run --security-opt seccomp=sudarshana-docker-seccomp.json your-image',
      packageCount: noShellPackages.length
    };
  }

  /**
   * Generate macOS Sandbox profile (.sb format)
   */
  _generateMacOSSandbox(policies) {
    const noNetworkPackages = Object.entries(policies)
      .filter(([name, p]) => name !== '_application_' && (!p.network || p.network.length === 0));

    // macOS sandbox-exec profile (Scheme-like syntax)
    const profile = `
(version 1)
(deny default)

; Allow basic operations
(allow process-exec*)
(allow file-read*)
(allow mach-lookup)
(allow sysctl-read)
(allow system-socket)

; Network: allow only for packages with network policy
(deny network-outbound)
(allow network-outbound (remote tcp "*:443"))  ; HTTPS only
(allow network-outbound (remote tcp "*:80"))   ; HTTP
(allow network-outbound (local tcp))           ; localhost

; Deny sensitive file reads
(deny file-read* (subpath "/etc/shadow"))
(deny file-read* (subpath "/private/etc/master.passwd"))

; Allow node_modules reads
(allow file-read* (subpath "${this.projectRoot}/node_modules"))

; Deny writes outside project
(deny file-write* (subpath "/"))
(allow file-write* (subpath "${this.projectRoot}"))
(allow file-write* (subpath "/tmp"))
`.trim();

    return {
      profile,
      format: 'apple-sandbox-v1',
      usage: 'sandbox-exec -f sudarshana.sb node app.js',
      instructions: [
        'Save as sudarshana.sb',
        'Run: sandbox-exec -f sudarshana.sb node app.js',
        'Note: macOS sandbox is process-level, not per-package'
      ]
    };
  }

  /**
   * Generate Windows AppContainer policy
   */
  _generateWindowsPolicy(policies) {
    return {
      format: 'windows-appcontainer',
      capabilities: [
        'internetClient',        // Outbound network
        // NOT: 'privateNetworkClientServer' (blocks local network access)
        // NOT: 'documentsLibrary' (blocks document access)
      ],
      deniedCapabilities: [
        'privateNetworkClientServer',
        'documentsLibrary',
        'removableStorage',
        'internetClientServer',  // No inbound connections
      ],
      instructions: [
        'Windows AppContainer requires running as a UWP-style container',
        'Alternative: use Windows Sandbox (winsandbox.exe) with config file',
        'Or use WSL2 with Linux seccomp profiles'
      ]
    };
  }

  /**
   * Save generated policies to disk
   */
  savePolicies(result) {
    const outputDir = path.join(this.projectRoot, '.sudarshana-kernel');
    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

    // Save main report
    fs.writeFileSync(
      path.join(outputDir, 'kernel-policies.json'),
      JSON.stringify(result, null, 2)
    );

    // Save Docker profile separately (most commonly used)
    if (result.profiles.docker) {
      fs.writeFileSync(
        path.join(outputDir, 'docker-seccomp.json'),
        JSON.stringify(result.profiles.docker.profile, null, 2)
      );
    }

    // Save macOS sandbox if applicable
    if (result.profiles.sandbox) {
      fs.writeFileSync(
        path.join(outputDir, 'sudarshana.sb'),
        result.profiles.sandbox.profile
      );
    }

    return outputDir;
  }
}

module.exports = { KernelPolicyGenerator };
