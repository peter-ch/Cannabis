// Disposable public configuration fixture; no global authority or project custody.
import { generateKeyPairSync } from 'node:crypto';
import { Wallet, ZeroAddress } from 'ethers';
const h=n=>'0x'+n.toString(16).padStart(64,'0');
export function launchFixture() {
  const keys=[Wallet.createRandom(),Wallet.createRandom()],pub=generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey.export({format:'jwk'});
  const configuration={schema:'cannabis.guest-launch-configuration.v1',configurationId:h(1),validFrom:1000,validUntil:2000,
    context:{chainId:31337,registryId:h(2),token:ZeroAddress},
    network:{rpc:'http://127.0.0.1:8545',chainId:31337,token:ZeroAddress,escrow:keys[0].address,genesisHash:h(3),escrowCodeHash:h(4),
      tokenCodeHash:null,finality:'rpc-finalized',maxFinalizedAgeSeconds:1800,maxHeadAgeSeconds:120},
    provider:keys[1].address,resourceId:h(5),execution:{profile:{schema:'cannabis.guest-native-service.v2',units:1,
      runtime:{adapter:'native-linux-x86_64-v1',architecture:'x86_64',os:'linux',digestSHA256:'bb'.repeat(32)},
      resources:{cpus:1,memoryMiB:128,scratchMiB:8,wallSeconds:60,nodes:1},
      total:{cpu_millis:3000,memory_bytes:1024**3,processes:192,wall_seconds:120,children:3},
      control:{cpu_millis:1000,memory_bytes:512*1024**2,processes:64,wall_seconds:120},
      helper:{cpu_millis:1000,memory_bytes:256*1024**2,processes:64,wall_seconds:60},
      processLimit:32,scratchInodes:512,staging:{bytes:16*1024**2,inodes:1024},ciphertext:{bytes:8*1024**2,inodes:64,inputBytes:4*1024**2,outputBytes:4*1024**2},maxInputBytes:1024**2,
      tools:{pythonSHA256:'aa'.repeat(32),ageSHA256:'bb'.repeat(32),ageKeygenSHA256:'cc'.repeat(32)}},
      source:{python:'/usr/bin/python3',rootfs:'/opt/cannabis/runtime',age:'/usr/local/bin/age',ciphertext:'/run/job/workload.age',destination:'/run/job/result.age'}},
    attestationPolicyTemplate:{schema:'cannabis.attestation.trustee-policy.v1',issuer:'Owned configuration fixture',signingJwk:pub,
      verifierBuild:'Owned signature fixture only',appraisalPolicyId:'owned-fixture',maxTokenAgeSeconds:90,maxTokenLifetimeSeconds:120,challengeTTLSeconds:90,
      tee:'snp',measurements:{launch:'aa'.repeat(48),initData:null,minimumTCB:{bootloader:1,tee:1,snp:1,microcode:1}}},
    bootstrap:{agentBinary:'/usr/local/bin/ttrpc-aa',bridgeBinary:'/usr/local/bin/api-server-rest',runtimeDirectory:'/run',port:8006},
    transport:{timeoutMs:60000,maxCiphertextBytes:4*1024*1024}};
  return {keys,configuration};
}
