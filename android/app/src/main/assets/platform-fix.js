/**
 * VSCodroid platform compatibility and extension execution runtime fix.
 *
 * 1. PLATFORM OVERRIDE:
 * Termux-patched Node.js reports process.platform === "android" instead of "linux".
 * VS Code extensions only recognize "win32", "darwin", and "linux". When extensions
 * observe "android", they either abort with "Unsupported platform", look for non-existent
 * "android-arm64" assets (Open VSX serves "linux-arm64" / "alpine-arm64"), or misclassify
 * the operating system (e.g. ms-python disables virtualenv activation).
 *
 * Platform is selectively overridden to "linux" when:
 *  - Running inside VS Code Server, Extension Host, or any extension context
 *  - Explicitly opted in (VSCODROID_PLATFORM_FIX=1, VSCODROID_FORCE_PLATFORM_LINUX=1)
 *  - node-gyp is detected in argv
 * Ordinary standalone user scripts (e.g. Rollup 4.57+, esbuild in terminal) retain
 * "android" so they can use native android-arm64 builds when available.
 *
 * 2. EXTENSION EXECUTION INTERCEPTION (child_process):
 * Android kernel SELinux policy (targetSdk >= 29) denies execve() on any binary or
 * script located under filesDir (~/.vscodroid/extensions/...), failing with EACCES (exit 126).
 * Furthermore, Android lacks /usr/bin/env and /bin/sh (ENOENT).
 *
 * child_process methods (spawn, spawnSync, execFile, execFileSync, fork, exec, execSync)
 * are hooked to:
 *  - Intercept ELF binaries in filesDir and execute them through the dynamic linker:
 *      * musl ELFs (e.g. Alpine arm64 from Open VSX): executed via libldmusl.so in nativeLibraryDir,
 *        with libseccomp-shim.so in LD_PRELOAD if available (fixes epoll_pwait2 on Android 13/14).
 *      * Bionic / Linux ELFs: executed via /system/bin/linker64.
 *  - Intercept shebang scripts (#!/usr/bin/env node, #!/bin/sh, #!/usr/bin/env python) and invoke
 *    the corresponding native interpreter directly.
 *  - Redirect /usr/bin/env and /bin/sh to valid Android paths (/system/bin/sh, nativeLibDir tools).
 *  - Guarantee that child process environment retains critical PATH and LD_LIBRARY_PATH entries,
 *    preventing "CANNOT LINK EXECUTABLE: library libz.so.1 not found".
 */
'use strict';

var fs = require('fs');
var path = require('path');

var isAndroid = process.platform === 'android' || process.env.VSCODROID_REAL_PLATFORM === 'android';

if (isAndroid) {
  process.env.VSCODROID_REAL_PLATFORM = 'android';

  var shouldFixPlatform = false;

  // Opt-in: npm/npx bash functions set this
  if (process.env.VSCODROID_PLATFORM_FIX === '1') {
    shouldFixPlatform = true;
    delete process.env.VSCODROID_PLATFORM_FIX; // don't propagate to children
  }

  if (process.env.VSCODROID_FORCE_PLATFORM_LINUX === '1') {
    shouldFixPlatform = true;
  }

  // Auto-detect node-gyp (spawned by npm as subprocess)
  var entry = (process.argv[1] || '').replace(/\\/g, '/');
  if (!shouldFixPlatform) {
    if (/(^|\/)node-gyp(-build)?(\/|\.js$|$)/.test(entry)) {
      shouldFixPlatform = true;
    }
  }

  // Auto-detect VS Code Server, Extension Host, and extensions
  if (!shouldFixPlatform) {
    var isVsCodeContext =
      process.argv.some(function (a) {
        if (typeof a !== 'string') return false;
        var normalized = a.replace(/\\/g, '/');
        return (
          normalized.indexOf('--type=extensionHost') !== -1 ||
          /(^|\/)bootstrap-fork(\.js)?$/.test(normalized) ||
          /(^|\/)server-main(\.js)?$/.test(normalized) ||
          /(^|\/)server(\.js)?$/.test(normalized)
        );
      }) ||
      Boolean(process.env.VSCODE_IPC_HOOK_EXTHOST) ||
      Boolean(process.env.VSCODE_ESM_ENTRYPOINT) ||
      Boolean(process.env.VSCODE_HANDLES_UNCAUGHT_ERRORS) ||
      Boolean(process.env.VSCODROID_EXTENSION_HOST) ||
      /(^|\/)\.vscodroid\/extensions\//.test(entry) ||
      /(^|\/)extensions\/[^/]+\//.test(entry) ||
      /(^|\/)vscode-reh\/out\//.test(entry);

    if (isVsCodeContext) {
      shouldFixPlatform = true;
    }
  }

  if (shouldFixPlatform) {
    Object.defineProperty(process, 'platform', {
      value: 'linux',
      writable: false,
      enumerable: true,
      configurable: true
    });
  }
}

// ---------------------------------------------------------------------------
// Child Process Hooking for Android Extension Execution
// ---------------------------------------------------------------------------

(function hookChildProcess() {
  // Only hook if running on Android or when test intercept is explicitly requested
  var active = isAndroid || process.env.VSCODROID_TEST_INTERCEPT === '1';
  if (!active) return;

  var cp = require('child_process');
  if (cp.__vscodroid_hooked) return;
  cp.__vscodroid_hooked = true;

  var nativeLibDir = process.env.VSCODROID_NATIVE_LIB_DIR || (process.execPath ? path.dirname(process.execPath) : '');
  var filesDir = process.env.VSCODROID_FILES_DIR || (process.env.PREFIX ? path.dirname(process.env.PREFIX) : '');
  if (!filesDir && process.env.HOME) {
    filesDir = path.dirname(process.env.HOME);
  }

  var muslLoaderPath = nativeLibDir ? path.join(nativeLibDir, 'libldmusl.so') : '';
  var seccompShimPath = nativeLibDir ? path.join(nativeLibDir, 'libseccomp-shim.so') : '';

  /**
   * Transforms spawn arguments to make execution compatible with Android SELinux,
   * non-existent desktop paths, and required dynamic linkers.
   */
  function transformArgs(command, rawArgs, rawOptions) {
    var args = Array.isArray(rawArgs) ? rawArgs.slice() : [];
    var options = (rawOptions && typeof rawOptions === 'object') ? Object.assign({}, rawOptions) : {};

    // 1. Environment sanitization
    var env = options.env ? Object.assign({}, options.env) : Object.assign({}, process.env);

    if (!env.PATH && process.env.PATH) {
      env.PATH = process.env.PATH;
    } else if (env.PATH && process.env.PATH) {
      var parts = env.PATH.split(':');
      if (nativeLibDir && parts.indexOf(nativeLibDir) === -1) {
        parts.unshift(nativeLibDir);
      }
      if (filesDir) {
        var tcbin = path.join(filesDir, 'usr/libexec/tcbin');
        var usrbin = path.join(filesDir, 'usr/bin');
        if (parts.indexOf(tcbin) === -1) parts.splice(1, 0, tcbin);
        if (parts.indexOf(usrbin) === -1) parts.splice(2, 0, usrbin);
      }
      env.PATH = parts.join(':');
    }

    if (process.env.LD_LIBRARY_PATH) {
      if (!env.LD_LIBRARY_PATH) {
        env.LD_LIBRARY_PATH = process.env.LD_LIBRARY_PATH;
      } else {
        var existing = env.LD_LIBRARY_PATH.split(':');
        var defaults = process.env.LD_LIBRARY_PATH.split(':');
        for (var d = defaults.length - 1; d >= 0; d--) {
          if (defaults[d] && existing.indexOf(defaults[d]) === -1) {
            existing.unshift(defaults[d]);
          }
        }
        env.LD_LIBRARY_PATH = existing.join(':');
      }
    }

    if (!env.TMPDIR && process.env.TMPDIR) env.TMPDIR = process.env.TMPDIR;
    if (!env.HOME && process.env.HOME) env.HOME = process.env.HOME;
    env.VSCODROID_FORCE_PLATFORM_LINUX = '1';
    options.env = env;

    // 2. Shell normalization
    if (options.shell === true || options.shell === '/bin/sh' || options.shell === '/usr/bin/sh') {
      options.shell = '/system/bin/sh';
    }

    var cmd = String(command || '');

    // 3. /usr/bin/env redirection
    if (cmd === '/usr/bin/env' || cmd === 'env' || /(^|\/)bin\/env$/.test(cmd)) {
      var idx = 0;
      while (idx < args.length) {
        var a = args[idx];
        if (a === '-S' || a === '--split-string') {
          idx++;
          if (idx < args.length) {
            var split = args[idx].split(/\s+/).filter(Boolean);
            args.splice(idx, 1);
            for (var s = split.length - 1; s >= 0; s--) {
              args.splice(idx, 0, split[s]);
            }
          }
          continue;
        }
        if (a.indexOf('=') !== -1 && !a.startsWith('/') && !a.startsWith('.')) {
          var eq = a.indexOf('=');
          env[a.slice(0, eq)] = a.slice(eq + 1);
          idx++;
        } else {
          break;
        }
      }
      if (idx < args.length) {
        cmd = args[idx];
        args = args.slice(idx + 1);
      }
    }

    // 4. /bin/sh redirection
    if (cmd === '/bin/sh' || cmd === '/usr/bin/sh') {
      cmd = '/system/bin/sh';
    }

    // 5. Bare command name resolution
    if (cmd.indexOf('/') === -1 && cmd.indexOf('\\') === -1) {
      if (cmd === 'node') {
        cmd = process.execPath || (nativeLibDir ? path.join(nativeLibDir, 'libnode.so') : 'node');
      } else if (cmd === 'python' || cmd === 'python3') {
        var pySo = nativeLibDir ? path.join(nativeLibDir, 'libpython.so') : '';
        var pyBin = filesDir ? path.join(filesDir, 'usr/bin/python3') : '';
        if (pySo && fs.existsSync(pySo)) cmd = pySo;
        else if (pyBin && fs.existsSync(pyBin)) cmd = pyBin;
      } else if (cmd === 'git' && nativeLibDir) {
        var gitSo = path.join(nativeLibDir, 'libgit.so');
        if (fs.existsSync(gitSo)) cmd = gitSo;
      } else if (cmd === 'rg' && nativeLibDir) {
        var rgSo = path.join(nativeLibDir, 'libripgrep.so');
        if (fs.existsSync(rgSo)) cmd = rgSo;
      } else if (cmd === 'bash' && nativeLibDir) {
        var bashSo = path.join(nativeLibDir, 'libbash.so');
        if (fs.existsSync(bashSo)) cmd = bashSo;
      } else if (cmd === 'sh') {
        cmd = '/system/bin/sh';
      } else if (env.PATH) {
        var dirs = env.PATH.split(':');
        for (var p = 0; p < dirs.length; p++) {
          var cand = path.join(dirs[p], cmd);
          try {
            if (fs.existsSync(cand)) {
              cmd = cand;
              break;
            }
          } catch (_) {}
        }
      }
    }

    var currentNativeLib = env.VSCODROID_NATIVE_LIB_DIR || process.env.VSCODROID_NATIVE_LIB_DIR || nativeLibDir;
    var currentFilesDir = env.VSCODROID_FILES_DIR || process.env.VSCODROID_FILES_DIR || filesDir;
    var currentMuslLoader = currentNativeLib ? path.join(currentNativeLib, 'libldmusl.so') : muslLoaderPath;
    var currentSeccompShim = currentNativeLib ? path.join(currentNativeLib, 'libseccomp-shim.so') : seccompShimPath;

    // 6. Inspect target binary or script
    // Avoid double-wrapping if already routed to linker or loader
    var isLinkerOrLoader =
      cmd === '/system/bin/linker64' ||
      cmd === '/system/bin/linker' ||
      (currentMuslLoader && cmd === currentMuslLoader);

    if (!isLinkerOrLoader) {
      var resolved = path.resolve(options.cwd || process.cwd(), cmd);
      var isFile = false;
      try {
        isFile = fs.existsSync(resolved) && fs.statSync(resolved).isFile();
      } catch (_) {}

      if (isFile) {
        var normResolved = resolved.replace(/\\/g, '/');
        var normNative = currentNativeLib ? currentNativeLib.replace(/\\/g, '/') : '';
        var normFiles = currentFilesDir ? currentFilesDir.replace(/\\/g, '/') : '';

        var isUnderNativeLib = normNative && normResolved.indexOf(normNative) === 0;
        var isSystemPath = normResolved.startsWith('/system/') || normResolved.startsWith('/apex/') || normResolved.startsWith('/vendor/');

        // If not in nativeLibDir or system partitions, SELinux prevents direct execve()
        var isUnderAppData = normResolved.indexOf('/data/data/') !== -1 ||
                             normResolved.indexOf('/data/user/') !== -1 ||
                             (normFiles && normResolved.indexOf(normFiles) !== -1) ||
                             process.env.VSCODROID_TEST_INTERCEPT === '1';

        if ((isUnderAppData && !isUnderNativeLib) || (!isUnderNativeLib && !isSystemPath && isAndroid)) {
          var header = null;
          try {
            var fd = fs.openSync(resolved, 'r');
            var buf = Buffer.alloc(4096);
            var n = fs.readSync(fd, buf, 0, 4096, 0);
            fs.closeSync(fd);
            header = buf.slice(0, n);
          } catch (_) {}

          if (header && header.length >= 2 && header[0] === 0x23 && header[1] === 0x21) {
            // Shebang script
            var firstLine = header.toString('utf8').split('\n')[0];
            if (firstLine.indexOf('node') !== -1) {
              cmd = process.execPath || (nativeLibDir ? path.join(nativeLibDir, 'libnode.so') : 'node');
              args = [resolved].concat(args);
            } else if (firstLine.indexOf('python') !== -1) {
              cmd = nativeLibDir ? path.join(nativeLibDir, 'libpython.so') : 'python3';
              args = [resolved].concat(args);
            } else if (firstLine.indexOf('bash') !== -1) {
              cmd = nativeLibDir ? path.join(nativeLibDir, 'libbash.so') : '/system/bin/sh';
              args = [resolved].concat(args);
            } else if (firstLine.indexOf('sh') !== -1) {
              cmd = '/system/bin/sh';
              args = [resolved].concat(args);
            }
          } else if (/\.(js|cjs|mjs)$/.test(resolved)) {
            // JS script
            cmd = process.execPath || (nativeLibDir ? path.join(nativeLibDir, 'libnode.so') : 'node');
            args = [resolved].concat(args);
          } else if (
            header &&
            header.length >= 4 &&
            header[0] === 0x7f &&
            header[1] === 0x45 &&
            header[2] === 0x4c &&
            header[3] === 0x46
          ) {
            // ELF binary
            var headerStr = header.toString('latin1');
            var isMusl = headerStr.indexOf('ld-musl') !== -1 || headerStr.indexOf('libc.musl') !== -1;

            if (isMusl && currentMuslLoader && fs.existsSync(currentMuslLoader)) {
              cmd = currentMuslLoader;
              args = [resolved].concat(args);

              if (currentSeccompShim && fs.existsSync(currentSeccompShim)) {
                if (env.LD_PRELOAD) {
                  if (env.LD_PRELOAD.indexOf(currentSeccompShim) === -1) {
                    env.LD_PRELOAD = env.LD_PRELOAD + ':' + currentSeccompShim;
                  }
                } else {
                  env.LD_PRELOAD = currentSeccompShim;
                }
              }
            } else {
              // Bionic / standard Linux ELF
              cmd = '/system/bin/linker64';
              args = [resolved].concat(args);
            }
          }
        }
      }
    }

    return { command: cmd, args: args, options: options };
  }

  cp.__vscodroid_transform = transformArgs;

  // --- Hook cp.spawn ---
  var origSpawn = cp.spawn;
  cp.spawn = function (cmd, rawArgs, rawOptions) {
    var transformed = transformArgs(cmd, rawArgs, rawOptions);
    return origSpawn.call(this, transformed.command, transformed.args, transformed.options);
  };

  // --- Hook cp.spawnSync ---
  var origSpawnSync = cp.spawnSync;
  cp.spawnSync = function (cmd, rawArgs, rawOptions) {
    var transformed = transformArgs(cmd, rawArgs, rawOptions);
    return origSpawnSync.call(this, transformed.command, transformed.args, transformed.options);
  };

  // --- Hook cp.execFile ---
  var origExecFile = cp.execFile;
  cp.execFile = function (file, rawArgs, rawOptions, rawCallback) {
    var args = rawArgs;
    var options = rawOptions;
    var callback = rawCallback;

    if (typeof args === 'function') {
      callback = args;
      args = [];
      options = {};
    } else if (typeof options === 'function') {
      callback = options;
      if (Array.isArray(args)) {
        options = {};
      } else {
        options = args || {};
        args = [];
      }
    }

    var transformed = transformArgs(file, args, options);
    return origExecFile.call(this, transformed.command, transformed.args, transformed.options, callback);
  };

  // --- Hook cp.execFileSync ---
  var origExecFileSync = cp.execFileSync;
  cp.execFileSync = function (file, rawArgs, rawOptions) {
    var args = Array.isArray(rawArgs) ? rawArgs : [];
    var options = (!Array.isArray(rawArgs) && typeof rawArgs === 'object') ? rawArgs : rawOptions;
    var transformed = transformArgs(file, args, options);
    return origExecFileSync.call(this, transformed.command, transformed.args, transformed.options);
  };

  // --- Hook cp.fork ---
  var origFork = cp.fork;
  cp.fork = function (modulePath, rawArgs, rawOptions) {
    var args = Array.isArray(rawArgs) ? rawArgs.slice() : [];
    var options = (!Array.isArray(rawArgs) && typeof rawArgs === 'object') ? Object.assign({}, rawArgs) : Object.assign({}, rawOptions);

    var forkExecArgv = options.execArgv ? options.execArgv.slice() : (process.execArgv || []).slice();
    var fixArg = '--require=' + __filename;
    if (!forkExecArgv.some(function (a) { return a.indexOf('platform-fix.js') !== -1; })) {
      forkExecArgv.push(fixArg);
    }
    options.execArgv = forkExecArgv;

    var env = options.env ? Object.assign({}, options.env) : Object.assign({}, process.env);
    env.VSCODROID_FORCE_PLATFORM_LINUX = '1';
    options.env = env;

    return origFork.call(this, modulePath, args, options);
  };

  // --- Hook cp.exec ---
  var origExec = cp.exec;
  cp.exec = function (cmd, rawOptions, rawCallback) {
    var options = rawOptions;
    var callback = rawCallback;
    if (typeof options === 'function') {
      callback = options;
      options = {};
    }
    options = options ? Object.assign({}, options) : {};
    var env = options.env ? Object.assign({}, options.env) : Object.assign({}, process.env);
    if (!env.PATH && process.env.PATH) env.PATH = process.env.PATH;
    if (!env.LD_LIBRARY_PATH && process.env.LD_LIBRARY_PATH) env.LD_LIBRARY_PATH = process.env.LD_LIBRARY_PATH;
    if (!options.shell || options.shell === '/bin/sh' || options.shell === '/usr/bin/sh') {
      options.shell = '/system/bin/sh';
    }
    options.env = env;
    return origExec.call(this, cmd, options, callback);
  };

  // --- Hook cp.execSync ---
  var origExecSync = cp.execSync;
  cp.execSync = function (cmd, rawOptions) {
    var options = rawOptions ? Object.assign({}, rawOptions) : {};
    var env = options.env ? Object.assign({}, options.env) : Object.assign({}, process.env);
    if (!env.PATH && process.env.PATH) env.PATH = process.env.PATH;
    if (!env.LD_LIBRARY_PATH && process.env.LD_LIBRARY_PATH) env.LD_LIBRARY_PATH = process.env.LD_LIBRARY_PATH;
    if (!options.shell || options.shell === '/bin/sh' || options.shell === '/usr/bin/sh') {
      options.shell = '/system/bin/sh';
    }
    options.env = env;
    return origExecSync.call(this, cmd, options);
  };
})();
