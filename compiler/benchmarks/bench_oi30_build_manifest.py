"""OI-30 deterministic-build manifest boundary perturbation experiment."""
from __future__ import annotations

import json, os, tempfile, time, hashlib
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
from dataclasses import asdict
from pathlib import Path

from blake3 import blake3
from benchmarks.bench_android_managed_bridge import ui_activity_fixture
from xax_apk_signing import RsaSigningCapability, encode_private_signing_capability
from xax_manifest import AndroidManifestSpec, android_manifest_semantics
import xax_build
from xax_build import (
    ArtifactKind, BuildCapability, BuildCapabilityKind, BuildEffect, CapabilityGrant, TypedBinding,
    build, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy,
)
from xax_compiler import (
    Block, Kind, Node, Operation, Terminator, ValueRef, android_arm64_shared_target,
    bits_type, constant, function, graph_fragment, object_with_refs, wasm32_target, x86_64_windows_target,
)

SCHEMA = "xax-oi30-build-manifest-evidence-v1"


def _simple(*, target=None, profile=None, number=7, answer=42, external_inputs=None, compiler_identity=None):
    b1,b32=bits_type(1),bits_type(32); flag=constant(b1,1); num=constant(b32,number); ans=constant(b32,answer)
    graph=graph_fragment((Block((),(Node(Operation.CONSTANT,(),(b32,),entity=ans),),Terminator.return_((ValueRef.node_result(0,0),))),))
    entry=function(graph,(),(b32,)); module=object_with_refs(Kind.MODULE,(b1,b32,flag,num,ans,entry))
    app=package(b"oi30-app",(module,),build_entries=((b"image",entry),),feature_types=((b"flag",b1),),configuration_types=((b"number",b32),))
    target=target or x86_64_windows_target(); profile=profile or build_profile(); policy=trust_policy()
    request=build_request(app,b"image",target,profile,features=(TypedBinding(b"flag",flag),),configuration=(TypedBinding(b"number",num),))
    objects=(b1,b32,flag,num,ans,graph,entry,module,app,target,profile,policy,request)
    ext=external_inputs or {}
    resolution=resolve_packages(request,objects,policy,b"oi30-resolver-v1",external_inputs=ext)
    reader=snapshot_store(resolution,objects)
    kw={"external_inputs":ext}
    if compiler_identity is not None: kw["compiler_identity"]=compiler_identity
    result=build(reader,request.cid,**kw)
    return result,resolution.snapshot.cid,request.cid


def _signer():
    raw=json.loads((Path(__file__).parents[1]/"tests"/"fixtures"/"android_v2_test_signer.json").read_text())
    return RsaSigningCapability(int(raw["modulus_hex"],16),int(raw["public_exponent"]),int(raw["private_exponent_hex"],16),bytes.fromhex(raw["certificate_der_hex"]))


def _signed(private_delta=0):
    ui=ui_activity_fixture(); manifest=android_manifest_semantics(AndroidManifestSpec("xax.generated","xax.generated.XaxActivity",min_sdk=28,target_sdk=35,version_code=1,launcher=True))
    base=_signer(); signer=RsaSigningCapability(base.modulus,base.public_exponent,base.private_exponent+private_delta,base.certificate_der)
    transport=encode_private_signing_capability(signer); cap=BuildCapability(BuildCapabilityKind.SIGN,bytes.fromhex(base.identity_sha256))
    module=object_with_refs(Kind.MODULE,(ui["activity_callback"],ui["listener_callback"],ui["activity_export"],ui["listener_export"],ui["ui_semantics"],manifest))
    app=package(b"oi30-android",(module,),build_entries=((b"apk",ui["activity_callback"]),),capabilities=(cap,))
    target=android_arm64_shared_target(); profile=build_profile(grants=(CapabilityGrant(b"oi30-android",cap),)); policy=trust_policy()
    request=build_request(app,b"apk",target,profile,requested_artifacts=(ArtifactKind.ANDROID_SIGNED_APK,))
    objects=(*tuple(ui["reader"].objects()),ui["activity_export"],ui["listener_export"],ui["ui_semantics"],manifest,module,app,target,profile,policy,request)
    inputs={blake3(transport).digest():transport}; resolution=resolve_packages(request,objects,policy,b"oi30-android-resolver-v1",external_inputs=inputs)
    reader=snapshot_store(resolution,objects); result=build(reader,request.cid,external_inputs=inputs,effects=(BuildEffect(b"oi30-android",cap,transport),))
    return result,resolution.snapshot.cid,request.cid,inputs


def _worker_simple(_):
    r,s,q=_simple()
    return r.key.hex(), r.artifact_digest.hex(), s.hex(), q.hex()


def _rec(result,snapshot,request):
    return {"build_key":result.key.hex(),"snapshot":snapshot.hex(),"request":request.hex(),"provenance":result.provenance.cid.hex(),"artifact_digest":result.artifact_digest.hex(),"artifact_bytes":len(result.artifact)}


def collect_evidence():
    base,snap,req=_simple(); rows=[]
    def add(name,category,r,s,q,expected): rows.append({"perturbation":name,"class":category,"expected":expected,**_rec(r,s,q),"key_same":r.key==base.key,"bytes_same":r.artifact==base.artifact})
    add("baseline","semantic",base,snap,req,"baseline")
    # Ambient process state: must not affect pure reproducible build.
    old=dict(os.environ); cwd=os.getcwd()
    try:
        os.environ.clear(); os.environ.update({"ZZ_BENIGN":"1","LC_ALL":"C","TZ":"UTC","SOURCE_DATE_EPOCH":"123"})
        with tempfile.TemporaryDirectory() as td:
            os.chdir(td); r,s,q=_simple(); add("cwd_env_locale_timezone_source_date","ambient",r,s,q,"unchanged")
    finally:
        os.chdir(cwd); os.environ.clear(); os.environ.update(old)
    # Metadata/input ordering and scheduling.
    ctx=multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=4, mp_context=ctx) as pool:
        results=list(pool.map(_worker_simple, range(4)))
    rows.append({"perturbation":"worker_count_4","class":"ambient","expected":"unchanged","all_key_same":all(x[0]==base.key.hex() for x in results),"all_bytes_same":all(x[1]==base.artifact_digest.hex() for x in results)})
    a1,a2=b"sdk-A",b"tool-B"
    d1,d2=blake3(a1).digest(),blake3(a2).digest()
    r1,s1,q1=_simple(external_inputs={d1:a1,d2:a2}); r2,s2,q2=_simple(external_inputs={d2:a2,d1:a1})
    rows.append({"perturbation":"metadata_external_order","class":"ambient","expected":"canonicalized","key_same":r1.key==r2.key,"bytes_same":r1.artifact==r2.artifact,"snapshot_same":s1==s2})
    # Declared identities/policy.
    alt_comp=blake3(b"oi30-alt-compiler").digest(); r,s,q=_simple(compiler_identity=alt_comp); add("compiler_identity","toolchain",r,s,q,"key_changes_bytes_stable")
    old_lower=xax_build.lowering_identity
    try:
        xax_build.lowering_identity=lambda a,f: blake3(b"oi30-alt-lowering"+bytes((a,f))).digest()
        r,s,q=_simple(); add("lowering_identity","toolchain",r,s,q,"key_changes_bytes_stable")
    finally: xax_build.lowering_identity=old_lower
    r,s,q=_simple(target=wasm32_target()); add("target","semantic",r,s,q,"key_and_bytes_change")
    r,s,q=_simple(profile=build_profile(optimization=1)); add("profile","build-policy",r,s,q,"key_changes")
    r,s,q=_simple(number=8); add("configuration","semantic",r,s,q,"key_changes")
    r,s,q=_simple(answer=43); add("build_program_semantics","semantic",r,s,q,"key_and_bytes_change")
    sdk=b"sdk-A"; ext={blake3(sdk).digest():sdk}; r,s,q=_simple(external_inputs=ext); add("external_sdk_digest","external",r,s,q,"key_changes")
    # Signing material is an explicit external input closure member after OI-30 fix.
    sign1,ss1,sr1,inp1=_signed(0); sign2,ss2,sr2,inp2=_signed(2)
    rows.append({"perturbation":"signing_material","class":"external","expected":"key_and_bytes_change","first":_rec(sign1,ss1,sr1),"second":_rec(sign2,ss2,sr2),"key_same":sign1.key==sign2.key,"bytes_same":sign1.artifact==sign2.artifact,"input_digest_same":next(iter(inp1))==next(iter(inp2))})
    # Signing algorithm is currently fixed by lowering implementation identity.
    rows.append({"perturbation":"signing_algorithm","class":"toolchain","expected":"fixed_by_android_signed_lowering_identity","lowering_identity":xax_build.ANDROID_SIGNED_APK_LOWERING_IDENTITY_V1.hex()})
    # Negative reproducible effects.
    negatives={}
    caps=[BuildCapability(BuildCapabilityKind.NETWORK),BuildCapability(BuildCapabilityKind.CLOCK),BuildCapability(BuildCapabilityKind.RANDOM)]
    for cap in caps:
        p=build_profile(grants=(CapabilityGrant(b"app",cap),)); b32=bits_type(32); c=constant(b32,1); g=graph_fragment((Block((),(Node(Operation.CONSTANT,(),(b32,),entity=c),),Terminator.return_((ValueRef.node_result(0,0),))),)); f=function(g,(),(b32,)); m=object_with_refs(Kind.MODULE,(b32,c,f)); app=package(b"app",(m,),build_entries=((b"image",f),),capabilities=(cap,)); t=x86_64_windows_target(); pol=trust_policy(); rq=build_request(app,b"image",t,p); objs=(b32,c,g,f,m,app,t,p,pol,rq); res=resolve_packages(rq,objs,pol,b"oi30-neg"); rd=snapshot_store(res,objs)
        try: build(rd,rq.cid,effects=(BuildEffect(b"app",cap),)); negatives[cap.kind.name]="accepted"
        except Exception as e: negatives[cap.kind.name]=getattr(getattr(e,"diagnostic",None),"rule",type(e).__name__)
    rows.append({"perturbation":"undeclared_environment","class":"ambient","expected":"unobservable_by_current_build_api","result":"no environment observation capability exists; benign environment perturbation above is byte/key stable"})
    return {"schema":SCHEMA,"policy":{"cache_key_inputs":["snapshot_root","request_root","compiler_identity","lowering_identity"],"snapshot_transitive_inputs":["package/build-entry","target","profile","features/configuration","trust/resolver","external_input_digests"],"ambient":"forbidden/unobservable in hermetic reproducible mode","signing_material":"BLAKE3 digest must be in snapshot external closure","signing_algorithm":"fixed by signed-APK lowering identity"},"rows":rows,"negative_effects":negatives}


def collect_timing(samples=11):
    def measure(fn):
        vals=[]
        for _ in range(samples):
            t=time.perf_counter_ns(); fn(); vals.append(time.perf_counter_ns()-t)
        vals.sort()
        return {"samples_ns":vals,"median_ns":vals[len(vals)//2],"min_ns":vals[0],"max_ns":vals[-1]}
    sdk=b"sdk-A"; ext={blake3(sdk).digest():sdk}
    return {"schema":"xax-oi30-build-manifest-timing-v1","samples":samples,"clean_build":measure(lambda:_simple()),"external_closure_build":measure(lambda:_simple(external_inputs=ext)),"signed_android_build":measure(lambda:_signed(0))}


def main(): print(json.dumps(collect_evidence(),indent=2,sort_keys=True))
if __name__=="__main__": main()
