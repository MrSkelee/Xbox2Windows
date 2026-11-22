float4 VSMain(uint vertex : SV_VertexID) : SV_Position
{
    // Pixel coordinates in a 64x64 viewport. The diagonal avoids pixel centers.
    // FLIP mirrors X so the failing draw control is asymmetric: the exact triangle
    // is symmetric across y == x, so a plain X/Y transpose would render identically.
    const float2 corners[3] = { float2(8, 8), float2(56.25, 8), float2(8, 56.25) };
#ifdef FLIP
    float2 pos = float2(64.0 - corners[vertex].x, corners[vertex].y);
#else
    float2 pos = corners[vertex];
#endif
    return float4(pos * float2(1.0 / 32, -1.0 / 32) + float2(-1, 1), 0, 1);
}

float4 PSMain() : SV_Target
{
    return float4(0, 1, 0, 1);
}
