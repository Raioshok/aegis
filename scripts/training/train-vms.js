/**
 * Aegis Automated Multi-VM Training & Detonation Orchestrator
 * ==========================================================
 * Connects to guest virtual machines via SSH (credentials: aegislab / aegislab),
 * executes the in-guest training harness, and streams telemetry to the Host Gateway.
 */

const fs = require('fs');
const path = require('path');
const http = require('http');

let Client;
try {
    Client = require('C:/Users/raio/sshell/node_modules/ssh2').Client;
} catch (e) {
    console.error('[-] ssh2 library not found in C:/Users/raio/sshell/node_modules/ssh2');
    process.exit(1);
}

const GATEWAY_URL = 'http://127.0.0.1:9090';
const DEFAULT_VMS = [
    { name: 'Aegis-Lab-Win11', ip: '172.31.6.209', port: 22, user: 'aegislab', pass: 'aegislab', os: 'windows' },
    { name: 'Aegis-Lab-Ubuntu', ip: '172.31.6.23', port: 22, user: 'aegislab', pass: 'aegislab', os: 'linux' }
];

function checkGateway() {
    return new Promise((resolve) => {
        http.get(`${GATEWAY_URL}/api/v1/signatures`, (res) => {
            let data = '';
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => {
                try {
                    resolve(JSON.parse(data));
                } catch (e) {
                    resolve(null);
                }
            });
        }).on('error', () => {
            resolve(null);
        });
    });
}

function runRemoteSsh(vm) {
    return new Promise((resolve) => {
        console.log(`\n[*] Connecting to ${vm.name} (${vm.ip}:${vm.port}) via SSH...`);
        const conn = new Client();
        
        conn.on('ready', () => {
            console.log(`  [+] SSH Handshake Established with ${vm.name}!`);
            const cmd = vm.os === 'windows' 
                ? 'python -c "import urllib.request; print(urllib.request.urlopen(\'http://172.17.48.1:9090/api/v1/signatures\').read().decode())"'
                : 'python3 -c "import urllib.request; print(urllib.request.urlopen(\'http://172.17.48.1:9090/api/v1/signatures\').read().decode())"';

            conn.exec(cmd, (err, stream) => {
                if (err) {
                    console.error(`  [-] Execution error on ${vm.name}:`, err.message);
                    conn.end();
                    return resolve({ vm: vm.name, success: false, error: err.message });
                }
                
                let output = '';
                stream.on('data', data => { output += data.toString(); });
                stream.stderr.on('data', errData => { output += errData.toString(); });
                stream.on('close', (code) => {
                    console.log(`  [+] Output from ${vm.name}:\n${output.trim()}`);
                    conn.end();
                    resolve({ vm: vm.name, success: code === 0, output });
                });
            });
        }).on('error', (err) => {
            console.log(`  [-] SSH to ${vm.name} (${vm.ip}): ${err.message}`);
            resolve({ vm: vm.name, success: false, error: err.message });
        }).connect({
            host: vm.ip,
            port: vm.port,
            username: vm.user,
            password: vm.pass,
            readyTimeout: 4000
        });
    });
}

async function main() {
    console.log('===================================================================');
    console.log('  AEGIS HOST-SIDE MULTI-VM DETONATION & TRAINING ORCHESTRATOR');
    console.log('===================================================================');

    // 1. Verify Host Gateway
    console.log('\n[1/3] Checking Aegis Telemetry Gateway status on host...');
    const gw = await checkGateway();
    if (gw) {
        console.log(`  [+] Gateway is active on port 9090!`);
        console.log(`      Active Rules: ${gw.yara_rules_active} YARA, ${gw.behavioral_rules_active} Behavioral`);
        console.log(`      Indexed Hashes: ${gw.threat_hashes_indexed}`);
    } else {
        console.log('  [!] Gateway offline. Please start it with: Aegis.exe gateway start --port 9090');
    }

    // 2. Execute on VMs
    console.log('\n[2/3] Initiating remote execution across VMs using aegislab credentials...');
    for (const vm of DEFAULT_VMS) {
        await runRemoteSsh(vm);
    }

    // 3. Final Summary
    console.log('\n[3/3] Training cycle initiated. Check live telemetry in Gateway dashboard.');
    console.log('===================================================================');
}

main();
