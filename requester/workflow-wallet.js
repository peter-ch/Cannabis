import {validateWorkflowReview} from './workflow-wallet-schema.mjs';
const check=v=>{if(!v)throw Error('Wallet selection changed or approval expired. Refresh the review.');};
export class WorkflowWallet {
  #provider;#epoch=0;#accounts=[];#changed;#onChange;
  constructor(changed=()=>{}) {this.#changed=changed;this.#onChange=()=>{this.#epoch++;this.#accounts=[];this.#changed();};}
  select(provider) {
    check(provider&&typeof provider.request==='function'&&typeof provider.on==='function'&&typeof provider.removeListener==='function');
    this.clear();this.#provider=provider;for(const e of ['accountsChanged','chainChanged','disconnect'])provider.on(e,this.#onChange);
  }
  clear(){if(this.#provider)for(const e of ['accountsChanged','chainChanged','disconnect'])this.#provider.removeListener(e,this.#onChange);
    this.#provider=undefined;this.#epoch++;this.#accounts=[];this.#changed();}
  async #call(method,params,until,signal,epoch=this.#epoch,connecting=false) {
    const selected=this.#provider;let timer,abort;
    const active=()=>check(selected&&selected===this.#provider&&(connecting||epoch===this.#epoch)&&!signal?.aborted&&Date.now()<until);
    active();const stopped=new Promise((_,reject)=>{abort=()=>reject(Error('Approval cancelled; dismiss any open wallet prompt.'));
      timer=setTimeout(abort,until-Date.now());signal?.addEventListener('abort',abort,{once:true});});
    try {const value=await Promise.race([stopped,Promise.resolve().then(()=>{active();return selected.request({method,...(params?{params}:{})});})]);
      active();return value;}finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);}
  }
  async connect(signal) {
    const until=Date.now()+60000,selected=this.#provider;
    const result=await this.#call('eth_requestAccounts',undefined,until,signal,this.#epoch,true);
    check(selected===this.#provider&&Array.isArray(result)&&result.length>0&&result.length<=64&&result.every(a=>/^0x[0-9a-fA-F]{40}$/.test(a)));
    const accounts=await this.#call('eth_accounts',undefined,until,signal);
    check(Array.isArray(accounts)&&accounts.map(a=>a.toLowerCase()).sort().join()===result.map(a=>a.toLowerCase()).sort().join());
    this.#accounts=accounts.map(a=>a.toLowerCase());return [...this.#accounts];
  }
  async sign(input,signal) {
    const r=validateWorkflowReview(input),epoch=this.#epoch;check(this.#accounts.includes(r.requester.toLowerCase()));
    const call=(method,params)=>this.#call(method,params,r.expiresAt,signal,epoch);
    const verify=async()=>{
      const accounts=await call('eth_accounts');check(Array.isArray(accounts)&&accounts.some(a=>a.toLowerCase()===r.requester.toLowerCase()));
      check(BigInt(await call('eth_chainId'))===BigInt(r.typedData.domain.chainId));
      const genesis=await call('eth_getBlockByNumber',['0x0',false]);check(genesis?.hash?.toLowerCase()===r.genesisHash.toLowerCase());
    };
    await verify();const signature=await call('eth_signTypedData_v4',[r.requester,JSON.stringify(r.typedData)]);await verify();
    check(typeof signature==='string'&&/^0x(?:[0-9a-fA-F]{2}){1,8192}$/.test(signature));return signature;
  }
}
