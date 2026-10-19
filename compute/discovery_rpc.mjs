// Operation-scoped JSON-RPC HTTP transport for public discovery reads.
import { performance } from 'node:perf_hooks';
export function boundedDiscoveryRPC({timeoutMs=60000,signal}={}) {
  if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>60000||signal&&!(signal instanceof AbortSignal))throw Error('Invalid discovery RPC budget');
  const controller=new AbortController(),start=performance.now();let closed=false;
  const abort=()=>controller.abort();signal?.addEventListener('abort',abort,{once:true});
  const timer=setTimeout(abort,timeoutMs);
  const active=()=>{
    if(closed||signal?.aborted||controller.signal.aborted||performance.now()-start>=timeoutMs)throw Error('Discovery RPC cancelled or expired');
  };
  return {
    async getUrl(request,cancelSignal) {
      active();cancelSignal?.checkSignal();cancelSignal?.addListener(abort);
      let reader;
      try {
        if(request.method!=='POST'||!request.body||request.body.length>262144)throw Error('Invalid discovery RPC request');
        const response=await fetch(request.url,{method:'POST',body:request.body,
          headers:{'Content-Type':'application/json',Accept:'application/json','Accept-Encoding':'identity'},
          redirect:'error',credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer',signal:controller.signal});
        active();
        if(response.status!==200||response.redirected||response.url!==request.url||
          !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('content-type')??'')||
          ![null,'identity'].includes(response.headers.get('content-encoding')))throw Error('Discovery RPC response refused');
        const declared=response.headers.get('content-length');
        if(declared!==null&&(!/^[1-9][0-9]{0,6}$/.test(declared)||Number(declared)>1048576))throw Error('Discovery RPC response exceeds bound');
        reader=response.body.getReader();const chunks=[];let bytes=0;
        while(true) {
          const part=await reader.read();active();if(part.done)break;
          bytes+=part.value.length;if(bytes>1048576)throw Error('Discovery RPC response exceeds bound');chunks.push(Buffer.from(part.value));
        }
        if(declared!==null&&Number(declared)!==bytes)throw Error('Truncated discovery RPC response');
        return {statusCode:200,statusMessage:'OK',headers:Object.fromEntries(response.headers),body:Buffer.concat(chunks)};
      } catch {abort();throw Error('Bounded discovery RPC failed');}
      finally {try{await reader?.cancel();}catch{}reader?.releaseLock();}
    },
    close(){closed=true;abort();clearTimeout(timer);signal?.removeEventListener('abort',abort);}
  };
}
