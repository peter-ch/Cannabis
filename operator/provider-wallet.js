// Browser-only, explicit wallet access. No key intake, transactions or generic
// signing fallback. A wallet prompt cannot be withdrawn through EIP-1193; late
// responses are discarded after cancellation, expiry or a wallet change.
const launchFields=[['role','uint8'],['configurationSHA256','bytes32'],['assignmentSHA256','bytes32'],
  ['leaseDigest','bytes32'],['bookingId','bytes32'],['requester','address'],['provider','address'],['validFrom','uint64'],['validUntil','uint64']];
const peerFields=[['role','uint8'],['genesisHash','bytes32'],...launchFields.slice(1,7),
  ['origin','string'],['channelBinding','bytes32'],['requesterNonce','bytes32'],['providerNonce','bytes32'],...launchFields.slice(7)];
const domainFields=[['name','string'],['version','string'],['chainId','uint256'],['verifyingContract','address']];
const check=v=>{if(!v)throw Error('Wallet approval changed, expired or is unsupported. Refresh the review.');};
const address=v=>typeof v==='string'&&/^0x[0-9a-fA-F]{40}$/.test(v)&&!/^0x0+$/.test(v);
const hash=v=>typeof v==='string'&&/^0x[0-9a-fA-F]{64}$/.test(v)&&!/^0x0+$/.test(v);
const exact=(v,keys)=>check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join());
const lower=v=>v.toLowerCase();
const uint=v=>(typeof v==='string'&&/^(?:0|[1-9][0-9]*|0x[0-9a-fA-F]+)$/.test(v)||Number.isSafeInteger(v)&&v>=0)&&BigInt(v)<2n**256n;
export function validateProviderReview(review) {
  check(review&&['launch','peer'].includes(review.kind)&&review.state==='awaiting-wallet'&&
    /^[0-9a-f]{64}$/.test(review.id)&&/^[0-9a-f]{64}$/.test(review.assignmentId)&&
    Number.isSafeInteger(review.expiresAt)&&review.expiresAt>Date.now()&&review.expiresAt<=Date.now()+61000&&
    address(review.signer)&&hash(review.genesisHash)&&hash(review.digest)&&
    review.executionAuthorized===false&&review.keyReleaseAuthorized===false);
  const data=review.typedData;exact(data,['domain','types','primaryType','message']);
  const type=review.kind==='launch'?'BookedGuestLaunch':'BookedPeerChannel',fields=review.kind==='launch'?launchFields:peerFields;
  check(data.primaryType===type);exact(data.types,['EIP712Domain',type]);exact(data.domain,domainFields.map(f=>f[0]));
  for(const [key,list] of [['EIP712Domain',domainFields],[type,fields]]) {
    check(Array.isArray(data.types[key])&&data.types[key].length===list.length);
    data.types[key].forEach((f,i)=>{exact(f,['name','type']);check(f.name===list[i][0]&&f.type===list[i][1]);});
  }
  check(data.domain.name===(review.kind==='launch'?'Cannabis booked guest launch':'Cannabis booked peer channel')&&
    data.domain.version==='1'&&uint(data.domain.chainId)&&BigInt(data.domain.chainId)>0n&&address(data.domain.verifyingContract));
  exact(data.message,fields.map(f=>f[0]));
  for(const [name,typeName] of fields) {
    const value=data.message[name];
    if(typeName==='bytes32')check(hash(value));
    else if(typeName==='address')check(address(value));
    else if(typeName.startsWith('uint'))check(uint(value)&&BigInt(value)<2n**BigInt(typeName.slice(4)));
    else {check(typeof value==='string'&&value.length<=512);const url=new URL(value);check(url.protocol==='https:'&&url.origin===value);}
  }
  check(BigInt(data.message.role)===1n&&lower(data.message.provider)===lower(review.signer)&&
    lower(data.message.assignmentSHA256)==='0x'+review.assignmentId&&BigInt(data.message.validUntil)>BigInt(data.message.validFrom));
  if(review.kind==='peer')check(lower(data.message.genesisHash)===lower(review.genesisHash)&&
    data.message.origin===review.summary.origin&&data.message.requesterNonce!==data.message.providerNonce);
  return structuredClone(review);
}

export class ProviderWallet {
  #provider;#epoch=0;#selection=0;#changed;#onChange;#accounts=[];
  constructor(onChange=()=>{}) {this.#changed=onChange;this.#onChange=()=>{++this.#epoch;this.#accounts=[];this.#changed();};}
  select(provider) {
    check(provider&&typeof provider.request==='function'&&typeof provider.on==='function'&&typeof provider.removeListener==='function');
    this.clear();this.#provider=provider;
    for(const event of ['accountsChanged','chainChanged','disconnect'])provider.on(event,this.#onChange);
  }
  clear() {
    if(this.#provider)for(const event of ['accountsChanged','chainChanged','disconnect'])this.#provider.removeListener(event,this.#onChange);
    this.#provider=undefined;++this.#epoch;++this.#selection;this.#accounts=[];this.#changed();
  }
  get accounts(){return [...this.#accounts];}
  async #call(method,params,epoch,expiresAt,signal,connecting=false) {
    const selected=this.#provider,selection=this.#selection;
    const active=()=>check(selected&&this.#provider===selected&&this.#selection===selection&&
      (connecting||this.#epoch===epoch)&&!signal?.aborted&&Date.now()<expiresAt);
    active();
    let timer,abort;
    const pending=Promise.resolve().then(()=>{
      active();return selected.request({method,...(params?{params}:{} )});
    });
    const stopped=new Promise((_,reject)=>{
      abort=()=>reject(Error('Wallet review cancelled. Dismiss any open wallet prompt.'));
      timer=setTimeout(abort,Math.max(1,expiresAt-Date.now()));signal?.addEventListener('abort',abort,{once:true});
    });
    try{const result=await Promise.race([pending,stopped]);active();return result;}
    finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);}
  }
  async connect(signal) {
    const expiresAt=Date.now()+60000,result=await this.#call('eth_requestAccounts',undefined,this.#epoch,expiresAt,signal,true);
    check(Array.isArray(result)&&result.length>0&&result.length<=64&&result.every(address));
    // Initial permission commonly emits accountsChanged. Verify the resulting
    // selection once stable instead of forcing a second connection prompt.
    const current=await this.#call('eth_accounts',undefined,this.#epoch,expiresAt,signal);
    check(Array.isArray(current)&&current.length===result.length&&current.every(address)&&
      current.map(lower).sort().join()===result.map(lower).sort().join());
    this.#accounts=current.map(lower);return this.accounts;
  }
  async sign(input,signal) {
    const review=validateProviderReview(input),epoch=this.#epoch;
    check(this.#accounts.includes(lower(review.signer)));
    const call=(method,params)=>this.#call(method,params,epoch,review.expiresAt,signal);
    const verify=async()=>{
      const accounts=await call('eth_accounts');
      check(Array.isArray(accounts)&&accounts.length<=64&&accounts.every(address)&&accounts.map(lower).includes(lower(review.signer)));
      const chain=await call('eth_chainId');check(uint(chain)&&BigInt(chain)===BigInt(review.typedData.domain.chainId));
      const genesis=await call('eth_getBlockByNumber',['0x0',false]);check(hash(genesis?.hash)&&lower(genesis.hash)===lower(review.genesisHash));
    };
    await verify();
    const signature=await call('eth_signTypedData_v4',[review.signer,JSON.stringify(review.typedData)]);
    check(typeof signature==='string'&&/^0x(?:[0-9a-fA-F]{2}){1,8192}$/.test(signature));
    await verify();return signature;
  }
}
