RaytracingAccelerationStructure scene : register(t0);
RWStructuredBuffer<uint4> results : register(u0);
struct Query { float4 originMin; float4 directionMax; uint mask; uint flags; };
StructuredBuffer<Query> queries : register(t1);

RayDesc make_ray(Query query)
{
    RayDesc ray;
    ray.Origin = query.originMin.xyz;
    ray.Direction = query.directionMax.xyz;
    ray.TMin = query.originMin.w;
    ray.TMax = query.directionMax.w;
    return ray;
}

#ifdef DXR_PIPELINE
struct Payload { uint4 value; };

[shader("raygeneration")]
void RayGen()
{
    uint i = DispatchRaysIndex().x;
    Query query = queries[i];
    Payload payload;
    payload.value = 0xffffffff;
    TraceRay(scene, RAY_FLAG_FORCE_OPAQUE, query.mask, 0, 1, 0, make_ray(query), payload);
    results[i] = payload.value;
}

[shader("miss")]
void Miss(inout Payload payload)
{
    payload.value = 0;
}

[shader("closesthit")]
void ClosestHit(inout Payload payload, BuiltInTriangleIntersectionAttributes attributes)
{
    payload.value = uint4(1, InstanceID(), PrimitiveIndex(), asuint(RayTCurrent()));
}
#else
[RootSignature("SRV(t0),UAV(u0),SRV(t1)")]
[numthreads(1, 1, 1)]
void CSMain(uint3 thread : SV_DispatchThreadID)
{
    uint i = thread.x;
    Query query = queries[i];
    RayQuery<RAY_FLAG_FORCE_OPAQUE> q;
    // Bit 31 is a fixture request to report facing; the low bits are ray flags.
    q.TraceRayInline(scene, query.flags & 0x3ff, query.mask, make_ray(query));
    while (q.Proceed()) {}
    uint4 value = uint4(0, 0, 0, 0);
    if (q.CommittedStatus() == COMMITTED_TRIANGLE_HIT) {
        uint status = 1;
        if ((query.flags >> 31) != 0 && q.CommittedTriangleFrontFace()) status = 3;
        value = uint4(status, q.CommittedInstanceID(), q.CommittedPrimitiveIndex(), asuint(q.CommittedRayT()));
    }
    results[i] = value;
}
#endif
