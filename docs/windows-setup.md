# Windows participant guide

Prepare your Cannabis identity in a guided Windows terminal. You do not need to edit JSON or supply a wallet seed. Your identity stays on your PC, with a password-encrypted portable backup that you control.

Community enrollment is preparing to open. This guide prepares custody and a private commitment request; it does not enroll you, issue a balance or send transactions. Use the same identity when the reviewed verification service opens. Dummy identities cannot qualify for community claims.

## Open the guide

1. Download the source ZIP from the [official repository](https://github.com/peter-ch/Cannabis) and extract it to a local folder. Check the release and source before running software.
2. Open `Start-Cannabis.cmd` and choose **Y**. No administrator access is needed.
3. The setup downloads portable Node.js 24.22.0 and age 1.3.2, checks their pinned SHA-256 digests, and installs the locked dependencies without package lifecycle scripts. It uses private per-user tool storage and changes no global PATH or security policy.
4. Choose **Create my identity**, or **Restore or verify a backup** if you already have one.
5. Choose **Save a password-encrypted backup**. Enter a new full filename on your backup storage. The age program asks for your passphrase directly in the terminal; the guide does not receive it.
6. Choose **Restore or verify a backup** and reopen that file with the same passphrase. Only after that succeeds, choose **Prepare my enrollment request**.

Use a long, unique backup passphrase and store it separately. A copy of the encrypted backup can live on another device or your chosen backup service. Copying only the local Windows-protected record does not provide portable recovery.

If Windows blocks PowerShell scripts, the launcher stops. Inspect the source and follow the policy approved for your computer, or ask its administrator. The launcher does not override execution policy, unblock downloaded scripts, disable antivirus or bypass application controls. A managed computer may therefore need administrator assistance. Setup requires network access for prerequisite downloads; custody and recovery run locally afterward. x64 and ARM64 Windows are supported by the pinned tool packages; ARM64 still needs platform validation before a reviewed release.

Download pins are recorded in `config/windows-tools.json`, using the official [Node.js checksums](https://nodejs.org/dist/v24.22.0/SHASUMS256.txt) and [age release assets](https://github.com/FiloSottile/age/releases/tag/v1.3.2). The public source and these pins are part of the software you review; a hash printed by an unrelated download page is not an independent trust source.

## What stays private

The local identity is stored in `%LOCALAPPDATA%\CannabisParticipant\identity\participant.json`, outside the source folder. The Semaphore identity is encrypted with age. Its separate age owner key is protected using Windows CurrentUser DPAPI, and the directory permits the current user and SYSTEM. The guide checks that decryption reproduces the expected identity commitment before saving a new identity.

The portable `.age` backup contains both the encrypted identity and its owner key, encrypted together using age's native passphrase format. Recovering it validates the commitment and rewraps the same owner key for the current Windows account. Existing different identities are not overwritten. Successful recovery is recorded locally; it does not certify personhood or authorize enrollment.

The enrollment request includes the commitment and preparation status. It contains no identity secret, owner key, receiving wallet, name, email or social graph. Keep it private until the official provider flow requests it. Do not post it alongside a receiving wallet. A provider must still verify one distinct person and bind the eventual enrollment to the canonical deployment.

No secret is intentionally written to plaintext files, command-line arguments, environment variables or logs. Secret bytes pass through local process pipes and remain temporarily in memory. The runtime cannot guarantee erasure of every string, operating-system copy, swap page or crash dump. Use a trusted Windows account and device. These implementation checks do not replace independent custody review.

## Invite a friend

Share the official project link yourself. Here is a suggested invitation:

> I'm helping get Cannabis ready: community claims, no proof-of-work, and an ambition to pay for useful private computing. If you're interested, read the project and use its Windows guide to prepare your own identity and backup. Enrollment isn't open yet. Keep your keys and backup passphrase to yourself.

Friends complete their own setup and verification. Do not collect their secret files or passwords. A few invited friends do not satisfy the contract's initial group requirement of 128 independently verified people.

Operator workflow checks use isolated local fixtures and are reported separately from actual participants or paid work. They are not community members, customers, trades or a source of public activity counts.

Open `Start-Local-Checks.cmd` for the separate operator flow, or run `npm run exercise:local` after installing the prerequisites. It starts a temporary loopback-only chain, uses 128 labeled fixture commitments, verifies an anonymous claim, and exercises an accepted arithmetic order through the 99% worker / 1% founder settlement and withdrawals. It stops its chain afterward and writes an explicitly labeled report under ignored `.runtime/`. The runner accepts no public RPC, private key or participant identity. It does not read your saved participant identity. Arithmetic fixtures do not establish confidential worker execution, real person verification or customer demand.

The first operator run downloads the depth-7 Semaphore 4.13.0 proving files from the project's artifact host, checks their exact sizes and pinned SHA-256 hashes, and awaits the complete download before proving. Later runs recheck the cached bytes. This download does not access a public blockchain.
