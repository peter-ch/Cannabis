// Observe actual kernel/manager state from inside the operator's selected unit.
// This local capability carries no attestation, signing or payment authority.
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const run=promisify(execFile),script=fileURLToPath(new URL('../scripts/start-operator.py',import.meta.url));
const check=v=>{if(!v)throw Error('Operator resource boundary unavailable; preserve recovery state');};
const integer=v=>Number.isSafeInteger(v)&&v>=0;
const identity=v=>JSON.stringify([v.profileSHA256,v.configurationSHA256,v.cgroupDevice,v.cgroupInode,
  v.stateVolume.mountId,v.stateVolume.rootDevice,v.stateVolume.rootInode,v.stateVolume.imageDevice,v.stateVolume.imageInode,v.stateVolume.recoveryInode]);

class OperatorBoundary {
  #file;#config;#identity;#current;#pending;#timer;#closed=false;#failed=false;
  constructor(file,config){this.#file=file;this.#config=config;}
  async check({minimumFreeBytes=8*1024**2}={}) {
    check(!this.#closed&&!this.#failed&&integer(minimumFreeBytes));
    this.#pending??=this.#observe().finally(()=>{this.#pending=null;});
    const value=await this.#pending;
    check(value.stateVolume.availableBytes>=minimumFreeBytes&&value.stateVolume.availableInodes>=64);
    return structuredClone(value);
  }
  async #observe(){
    const {stdout,stderr}=await run('/usr/bin/python3',['-I','-B',script,'--inspect',this.#file,String(process.pid)],{
      timeout:10000,maxBuffer:16384,windowsHide:true,env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8',PYTHONDONTWRITEBYTECODE:'1'}});
    const v=JSON.parse(stdout);
    check(!stderr&&v.schema==='cannabis.operator-boundary-observation.v1'&&v.configurationSHA256===this.#config&&
      /^[0-9a-f]{64}$/.test(v.profileSHA256)&&v.hardwareValidated===false&&v.paymentAuthorized===false&&
      integer(v.stateVolume?.availableBytes)&&integer(v.stateVolume?.availableInodes)&&integer(v.memoryCurrentBytes)&&integer(v.pidsCurrent));
    if(this.#identity)check(this.#identity===identity(v));else this.#identity=identity(v);
    this.#current=v;return v;
  }
  monitor(){
    check(!this.#timer&&!this.#closed);
    this.#timer=setInterval(()=>{void this.check().catch(()=>{
      if(!this.#closed&&!this.#failed){this.#failed=true;clearInterval(this.#timer);
        // The installed CLI owns SIGTERM cleanup. PID 1's control-group kill is
        // the bounded fallback if the owner cannot finish or has already died.
        process.kill(process.pid,'SIGTERM');}
    });},5000);this.#timer.unref();
  }
  snapshot(){return this.#current?{state:this.#failed?'unavailable':'observed',...structuredClone(this.#current)}:{state:'unavailable'};}
  async close(){this.#closed=true;clearInterval(this.#timer);await this.#pending?.catch(()=>{});}
}

export async function openOperatorBoundary(profileFile,configurationSHA256){
  check(process.platform==='linux'&&process.geteuid()===0&&typeof profileFile==='string'&&path.isAbsolute(profileFile)&&
    /^[0-9a-f]{64}$/.test(configurationSHA256));
  const boundary=new OperatorBoundary(profileFile,configurationSHA256);await boundary.check();return boundary;
}
