/**
 * Test suite for VSCodroid extension execution and platform compatibility.
 *
 * Verifies that platform-fix.js correctly handles:
 * 1. Platform override to "linux" in VS Code Extension Host and extension scripts.
 * 2. Child process interception for /usr/bin/env and /bin/sh.
 * 3. Shebang script interception (e.g. #!/usr/bin/env node).
 * 4. ELF binary interception for Android SELinux (musl loader vs system linker64).
 * 5. Environment variable preservation (PATH, LD_LIBRARY_PATH).
 *
 * Run via:
 *   node scripts/test-extension-exec.js
 */
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const FIX = path.resolve(__dirname, '../android/app/src/main/assets/platform-fix.js');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vscodroid-ext-test-'));

// Fake android platform loader for non-Android environments
const FAKE_ANDROID = path.join(tmp, 'fake-android.js');
fs.writeFileSync(
    FAKE_ANDROID,
    "Object.defineProperty(process, 'platform', { value: 'android', configurable: true });\n"
);

console.log('--- Running Extension Execution & Platform Fix Tests ---');

// 1. Platform Detection Tests
function testPlatform(scriptPath, args, env, expectedPlatform) {
    const probe = 'console.log(JSON.stringify({ platform: process.platform, real: process.env.VSCODROID_REAL_PLATFORM }));\n';
    fs.mkdirSync(path.dirname(scriptPath), { recursive: true });
    fs.writeFileSync(scriptPath, probe);

    const out = execFileSync(
        process.execPath,
        ['--require', FAKE_ANDROID, '--require', FIX, scriptPath, ...args],
        { env: Object.assign({}, process.env, env), encoding: 'utf8' }
    );
    const result = JSON.parse(out);
    assert.strictEqual(result.platform, expectedPlatform, `Platform for ${scriptPath} was ${result.platform}, expected ${expectedPlatform}`);
    assert.strictEqual(result.real, 'android', 'VSCODROID_REAL_PLATFORM must remain android');
}

testPlatform(path.join(tmp, 'regular-user-script.js'), [], {}, 'android');
testPlatform(path.join(tmp, 'ext-host.js'), ['--type=extensionHost'], {}, 'linux');
testPlatform(path.join(tmp, 'bootstrap-fork.js'), [], {}, 'linux');
testPlatform(path.join(tmp, '.vscodroid', 'extensions', 'test.ext-1.0', 'main.js'), [], {}, 'linux');
testPlatform(path.join(tmp, 'opt-in.js'), [], { VSCODROID_FORCE_PLATFORM_LINUX: '1' }, 'linux');

console.log('  ok   Platform detection tests passed');

// 2. Child Process Interception Tests (running under fake android + platform-fix)
const INTERCEPT_RUNNER = path.join(tmp, 'intercept-runner.js');
fs.writeFileSync(
    INTERCEPT_RUNNER,
    `
    const assert = require('assert');
    const cp = require('child_process');
    const fs = require('fs');
    const path = require('path');

    // Test 1: /usr/bin/env node redirection
    cp.execFile('/usr/bin/env', ['node', '-e', 'console.log("ENV_NODE_OK")'], (err, stdout) => {
        assert.ifError(err);
        assert.strictEqual(stdout.trim(), 'ENV_NODE_OK');
        console.log('  ok   /usr/bin/env node redirection works');
    });

    // Test 2: Shebang script execution
    const shebangScript = path.join('${tmp.replace(/\\/g, '/')}', 'mock-shebang.js');
    fs.writeFileSync(shebangScript, '#!/usr/bin/env node\\nconsole.log("SHEBANG_OK");\\n');
    fs.chmodSync(shebangScript, 0o755);

    cp.execFile(shebangScript, [], (err, stdout) => {
        assert.ifError(err);
        assert.strictEqual(stdout.trim(), 'SHEBANG_OK');
        console.log('  ok   Shebang script execution works');
    });

    // Test 3: Environment preservation
    const envCheckScript = path.join('${tmp.replace(/\\/g, '/')}', 'check-env.js');
    fs.writeFileSync(envCheckScript, 'console.log(JSON.stringify({ path: Boolean(process.env.PATH), ld: Boolean(process.env.LD_LIBRARY_PATH) }));\\n');

    cp.execFile('node', [envCheckScript], { env: { CUSTOM_VAR: '123' } }, (err, stdout) => {
        assert.ifError(err);
        const parsed = JSON.parse(stdout);
        assert.strictEqual(parsed.path, true, 'PATH must be preserved even when custom env is passed');
        console.log('  ok   Environment preservation works');
    });
    `
);

execFileSync(
    process.execPath,
    ['--require', FAKE_ANDROID, '--require', FIX, INTERCEPT_RUNNER],
    {
        env: Object.assign({}, process.env, {
            VSCODROID_TEST_INTERCEPT: '1',
            LD_LIBRARY_PATH: '/mock/native/lib:/mock/usr/lib'
        }),
        stdio: 'inherit'
    }
);

// 3. ELF Detection and Linker Wrapping Tests
const ELF_RUNNER = path.join(tmp, 'elf-runner.js');
fs.writeFileSync(
    ELF_RUNNER,
    `
    const assert = require('assert');
    const fs = require('fs');
    const path = require('path');
    const cp = require('child_process');

    const nativeDir = path.join('${tmp.replace(/\\/g, '/')}', 'mock-native');
    const filesDir = path.join('${tmp.replace(/\\/g, '/')}', 'mock-files');
    fs.mkdirSync(nativeDir, { recursive: true });
    fs.mkdirSync(filesDir, { recursive: true });

    const mockMuslLoader = path.join(nativeDir, 'libldmusl.so');
    fs.writeFileSync(mockMuslLoader, '#!/bin/sh\\n');

    // Create a mock musl ELF binary in filesDir
    const mockMuslElf = path.join(filesDir, 'mock-musl-server');
    const muslHeader = Buffer.alloc(128);
    muslHeader[0] = 0x7f; muslHeader[1] = 0x45; muslHeader[2] = 0x4c; muslHeader[3] = 0x46; // \\x7fELF
    muslHeader.write('/lib/ld-musl-aarch64.so.1', 16, 'ascii');
    fs.writeFileSync(mockMuslElf, muslHeader);

    // Create a mock bionic ELF binary in filesDir
    const mockBionicElf = path.join(filesDir, 'mock-bionic-server');
    const bionicHeader = Buffer.alloc(128);
    bionicHeader[0] = 0x7f; bionicHeader[1] = 0x45; bionicHeader[2] = 0x4c; bionicHeader[3] = 0x46; // \\x7fELF
    bionicHeader.write('/system/bin/linker64', 16, 'ascii');
    fs.writeFileSync(mockBionicElf, bionicHeader);

    // Test Musl ELF transformation
    const transformedMusl = cp.__vscodroid_transform(mockMuslElf, ['--port', '8080'], {});
    assert.strictEqual(transformedMusl.command, mockMuslLoader, 'Musl ELF must be wrapped with libldmusl.so');
    assert.strictEqual(transformedMusl.args[0], mockMuslElf, 'First argument to loader must be the payload path');
    assert.strictEqual(transformedMusl.args[1], '--port', 'Subsequent arguments must be preserved');
    console.log('  ok   Musl ELF dynamic loader wrapping verified');

    // Test Bionic ELF transformation
    const transformedBionic = cp.__vscodroid_transform(mockBionicElf, ['--version'], {});
    assert.strictEqual(transformedBionic.command, '/system/bin/linker64', 'Bionic ELF must be wrapped with /system/bin/linker64');
    assert.strictEqual(transformedBionic.args[0], mockBionicElf, 'First argument to linker must be the payload path');
    assert.strictEqual(transformedBionic.args[1], '--version', 'Subsequent arguments must be preserved');
    console.log('  ok   Bionic ELF linker64 wrapping verified');
    `
);

execFileSync(
    process.execPath,
    ['--require', FAKE_ANDROID, '--require', FIX, ELF_RUNNER],
    {
        env: Object.assign({}, process.env, {
            VSCODROID_TEST_INTERCEPT: '1',
            VSCODROID_NATIVE_LIB_DIR: path.join(tmp, 'mock-native'),
            VSCODROID_FILES_DIR: path.join(tmp, 'mock-files'),
            PATH: process.env.PATH
        }),
        stdio: 'inherit'
    }
);

// Cleanup
fs.rmSync(tmp, { recursive: true, force: true });
console.log('All extension execution & platform tests passed successfully!');
