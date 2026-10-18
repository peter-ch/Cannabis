# Your worker console

The Cannabis worker console shows actual CPU activity, memory use and local hardware inventory in a browser window. It is available in the [project source](https://github.com/peter-ch/Cannabis). It currently observes the computer and explains the requirements for admission; it cannot accept customer jobs or earn payments yet.

## Open the console

On Windows, install Node.js 22.22 or later, download the project source and double-click `Start-Cannabis-Worker.cmd`. Chrome opens the console when installed; otherwise Windows opens the default browser. Keep the command window open. Press Ctrl+C there to stop the local server.

From the project source directory on another platform, run:

~~~sh
npm run worker:console
~~~

Open `http://127.0.0.1:4201/`. The console uses Node's built-in modules and does not require a dependency installation. The older Windows participant kit is a separate release and does not contain this console.

## Read the observations

CPU and memory figures describe the whole computer, including unrelated applications. Windows graphics names come from the operating system; other platforms may report graphics inventory as unavailable. Neither hardware discovery nor utilization establishes confidential execution, useful completed work or billable usage.

Refresh requests a current observation. Pause monitoring stops automatic updates in that browser view; it does not stop the server or other software. Resume restarts observation. If the connection fails, the page explicitly marks retained readings as stale. Save readiness report downloads the latest successful observation, with its timestamp and admission limitations. The report contains hardware names but no account names, device serial numbers, wallets or content keys. Review it before sharing.

## Before a paid worker can start

The Start paid worker control remains disabled in this release. There is no hidden start endpoint or setting that enables paid work. Admission needs a fresh vendor-verified hardware report bound to the approved guest and assignment, a measured isolated launcher, protected storage/devices/networking, cleanup and key retirement, reviewed payment contracts and provider terms, and a real end-to-end acceptance run. See [worker deployment](worker-deployment.md) and [confidential computation](confidential-compute.md).

Ordinary desktop hardware and the website hosting servers are not automatically eligible. A remotely operated confidential worker could later be controlled from a desktop GUI, provided the attestation and key-release path is validated. No plaintext fallback is permitted.

The process listens only on loopback, serves an explicit asset list, refuses foreign hosts/origins and exposes read-only status. It has no job submission, remote command, customer-content, custody or payment interface. Do not publish or reverse-proxy port 4201.

## Computing and issuance

Cannabis uses Ethereum proof-of-stake settlement. Workers are paid for accepted computing services; they do not mine new tokens. The fixed cap, community claims and vested founder allocation remain as described in the [terms](tokenomics.md). Local observations and a running GUI do not establish a mainnet launch. Canonical release information belongs in the [mainnet release guide](mainnet-release.md).
