// Native ETH gifts only. The donor reviews and signs in their own wallet.
(() => {
  const root = document.querySelector('[data-donate]');
  if (!root) return;
  const recipient = '0xe02Ad92413aD0a3Aac8263eE3C2Bd9410955F89b';
  const baseURI = `ethereum:${recipient}@1`;
  const amount = root.querySelector('#donation-amount');
  const form = root.querySelector('form');
  const send = root.querySelector('[data-donate-send]');
  const mobile = root.querySelector('[data-donate-mobile]');
  const status = root.querySelector('[data-donate-status]');
  const walletList = root.querySelector('#donation-wallet');
  const providers = [];
  let busy = false;

  function wei() {
    const text = amount.value.trim();
    if (!/^(?:0|[1-9]\d*)(?:\.\d{1,18})?$/.test(text) || text.length > 40) throw Error('Enter a positive ETH amount with up to 18 decimal places.');
    const [whole, fraction = ''] = text.split('.');
    const value = BigInt(whole) * 10n ** 18n + BigInt(fraction.padEnd(18, '0'));
    if (value <= 0n || value >= 2n ** 256n) throw Error('Enter a positive ETH amount.');
    return value;
  }
  function updateAmount() {
    amount.setCustomValidity('');
    try {
      mobile.href = `${baseURI}?value=${wei()}`;
      mobile.removeAttribute('aria-disabled');
    } catch (error) {
      amount.setCustomValidity(error.message);
      mobile.removeAttribute('href');
      mobile.setAttribute('aria-disabled', 'true');
    }
    for (const preset of root.querySelectorAll('[data-donation-amount]')) {
      preset.setAttribute('aria-pressed', String(preset.dataset.donationAmount === amount.value));
    }
  }
  amount.addEventListener('input', updateAmount);
  for (const preset of root.querySelectorAll('[data-donation-amount]')) {
    preset.addEventListener('click', () => { amount.value = preset.dataset.donationAmount; updateAmount(); });
  }
  mobile.addEventListener('click', event => {
    if (busy || mobile.getAttribute('aria-disabled') === 'true') { event.preventDefault(); amount.reportValidity(); }
    else status.textContent = 'Your wallet app opens if it supports Ethereum payment links. Review the address, amount and network fee there. You can also scan the QR code or copy the address.';
  });
  root.querySelector('[data-copy-donation]').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(recipient); status.textContent = 'Founder address copied. Choose Ethereum mainnet when sending ETH.'; }
    catch { status.textContent = 'Copy the founder address from the text above, then paste it into your wallet.'; }
  });

  function addProvider(provider, name) {
    if (!provider || typeof provider.request !== 'function' || providers.some(item => item.provider === provider)) return;
    const index = providers.push({ provider }) - 1;
    const option = document.createElement('option');
    option.value = String(index);
    option.textContent = String(name || 'Browser wallet').slice(0, 80);
    walletList.append(option);
    root.querySelector('[data-wallet-choice]').hidden = providers.length < 2;
  }
  window.addEventListener('eip6963:announceProvider', event => {
    try { addProvider(event.detail.provider, event.detail.info.name); } catch { /* Ignore malformed announcements. */ }
  });
  window.dispatchEvent(new Event('eip6963:requestProvider'));
  // Wait for modern announcements before adding the legacy injection fallback.
  setTimeout(() => { if (!providers.length) addProvider(window.ethereum, 'Browser wallet'); }, 250);

  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy || !form.reportValidity()) return;
    let value;
    try { value = wei(); } catch (error) { status.textContent = error.message; return; }
    if (!providers.length) addProvider(window.ethereum, 'Browser wallet');
    const provider = providers[Number(walletList.value)]?.provider;
    if (!provider) { status.textContent = 'No browser wallet found. Open your wallet app using the link below, scan the QR code, or copy the address.'; return; }
    busy = true;
    const controls = [...form.querySelectorAll('button, input, select')];
    controls.forEach(control => { control.disabled = true; });
    status.textContent = `Review ${amount.value} ETH to the founder in your wallet. The network fee is additional.`;
    try {
      const accounts = await provider.request({ method: 'eth_requestAccounts' });
      const from = accounts?.[0];
      if (!/^0x[0-9a-f]{40}$/i.test(from || '')) throw Error('No wallet account was selected.');
      let chain = await provider.request({ method: 'eth_chainId' });
      if (BigInt(chain) !== 1n) {
        await provider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: '0x1' }] });
      }
      chain = await provider.request({ method: 'eth_chainId' });
      if (BigInt(chain) !== 1n) throw Error('Select Ethereum mainnet in your wallet, then try again.');
      const current = await provider.request({ method: 'eth_accounts' });
      if (current?.[0]?.toLowerCase() !== from.toLowerCase()) throw Error('The selected account changed. Review it and try again.');
      const hash = await provider.request({ method: 'eth_sendTransaction', params: [{ from, to: recipient, value: `0x${value.toString(16)}`, chainId: '0x1' }] });
      if (!/^0x[0-9a-f]{64}$/i.test(hash || '')) throw Error('Your wallet returned no valid transaction reference. Check its activity before trying again.');
      status.textContent = 'Thank you. Your donation was submitted and is awaiting network confirmation. ';
      const receipt = document.createElement('a');
      receipt.href = `https://etherscan.io/tx/${hash}`;
      receipt.textContent = 'Track your transaction ↗';
      receipt.target = '_blank'; receipt.rel = 'noopener noreferrer';
      status.append(receipt);
    } catch (error) {
      const code = error?.code ?? error?.data?.originalError?.code;
      status.textContent = code === 4001 ? 'Wallet request cancelled. No donation was submitted by this page.'
        : code === -32002 ? 'A request is already open in your wallet. Review it there.'
        : code === 4902 ? 'Ethereum mainnet is unavailable in this wallet. Choose another wallet or scan the QR code.'
        : code === -32603 || code === -32000 ? 'The wallet could not complete this request. Check your ETH balance, network fee and wallet activity before trying again.'
        : error?.message && !('code' in Object(error)) ? error.message
        : 'The wallet request could not be completed. Check your wallet activity before trying again, or use the QR code.';
    } finally {
      busy = false;
      controls.forEach(control => { control.disabled = false; });
    }
  });
  root.querySelector('[data-donate-tools]').hidden = false;
  root.querySelector('[data-copy-donation]').hidden = false;
  updateAmount();
})();
