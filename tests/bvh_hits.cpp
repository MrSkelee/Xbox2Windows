#define NOMINMAX
#include "bvh_fixture.h"
#include "dxr_fixture.h"
#include "TraceHits.h"
#include "WriteScene.h"
#include "ExpandLeaves.h"
#include <algorithm>

using namespace bvh_fixture;
namespace {
constexpr Word leaves = 64, sceneRows = 5 * leaves, epochs = 3;
constexpr std::uint64_t base = 0x12345678fffff7e0ull;
constexpr Word miss = UINT32_MAX;

Word bits(float value) {
    Word result;
    std::memcpy(&result, &value, sizeof(result));
    return result;
}
Row pack(float x, float y, float z, Word last) {
    return {bits(x), bits(y), bits(z), last};
}
struct Leaf {
    float x, y, z;
    Word id;
    bool readable, degenerate;
};
using Scene = std::array<Leaf, leaves>;

Scene make_scene(Word epoch) {
    Scene scene{};
    for (Word i = 0; i < leaves; ++i) {
        // The dense epoch gives every adjacent pair equal depths.
        const bool dense = epoch == 1;
        scene[i] = {dense ? 0.f : float(4 * (i % 8)), 0,
                    dense ? float(1 + (63-i)/2) : float(1 + i/8),
                    101 + (37*i)%64, epoch != 2 || (i != 31 && i != 32),
                    epoch == 2 && i == 63};
    }
    return scene;
}
std::vector<Row> serialize(const Scene& scene, Word epoch) {
    std::vector<Row> rows(sceneRows);
    for (Word i = 0; i < leaves; ++i) {
        const auto& leaf = scene[i];
        Word triangle = 2 * leaves + 3 * ((13*i + epoch*7) % leaves);
        std::uint64_t address = base + triangle * sizeof(Row);
        if (!leaf.readable)
            address = i == 31 ? address + (1ull << 32) : base + rows.size()*sizeof(Row) - 8;
        rows[2*i] = pack(leaf.x, leaf.y, leaf.z, static_cast<Word>(address));
        rows[2*i+1] = pack(leaf.x+2, leaf.y+2, leaf.z, static_cast<Word>(address >> 32));
        rows[triangle] = pack(leaf.x, leaf.y, leaf.z, 0);
        rows[triangle+1] = pack(leaf.x+2, leaf.y, leaf.z, 0);
        rows[triangle+2] = pack(leaf.x, leaf.y + (leaf.degenerate ? 0 : 2), leaf.z, leaf.id);
    }
    return rows;
}
using dxr_fixture::Ray;
std::vector<Ray> make_rays() {
    std::vector<Ray> rays;
    // An exact closed interval isolates every leaf in the sparse scene.
    for (Word i = 0; i < leaves; ++i) {
        const float t = float(1 + i/8);
        rays.push_back({float(4*(i%8))+.5f, .5f, 0, t, 0, 0, 1, t});
    }
    for (Word column = 0; column < 8; ++column) {
        const float x = float(4 * column);
        rays.push_back({x+.5f,.5f,0,0, 0,0,1,40});      // Front.
        rays.push_back({x+.5f,.5f,40,0, 0,0,-1,40});   // Back.
        rays.push_back({x+1.5f,1.5f,0,0, 0,0,1,40});   // Inside boxes, outside triangles.
        rays.push_back({x+1,1,0,0, 0,0,1,40});         // On the hypotenuse.
        rays.push_back({x,0,0,0, 0,0,1,40});           // On a vertex.
        rays.push_back({x+.5f,.5f,4,0, 0,0,1,0});      // Origin on triangle, t = 0.
        rays.push_back({x+.5f,.5f,0,3.25f, 0,0,1,3.75f});
        rays.push_back({x-1,.25f,0,0, .5f,.125f,1,40});
    }
    rays.push_back({0,0,0,0, 1,0,0,40});               // Parallel, off every plane.
    rays.push_back({-1,.5f,1,0, 1,0,0,40});            // In the first row's plane.
    rays.push_back({-1,.5f,1,0, 1,0,0,9});             // Ends on the third box's face.
    rays.push_back({-10,-10,0,0, 0,0,1,40});
    return rays;
}
// Closed parametric overlap of a ray lying in a leaf's plane with its 2x2 square.
bool in_plane_box(const Leaf& leaf, const Ray& r) {
    double nearT = r.nearT, farT = r.farT;
    const double origin[]{r.x, r.y}, direction[]{r.dx, r.dy}, low[]{leaf.x, leaf.y};
    for (int axis = 0; axis < 2; ++axis) {
        if (direction[axis] == 0) {
            if (origin[axis] < low[axis] || origin[axis] > low[axis] + 2) return false;
            continue;
        }
        const double a = (low[axis] - origin[axis]) / direction[axis];
        const double b = (low[axis] + 2 - origin[axis]) / direction[axis];
        nearT = std::max(nearT, std::min(a, b));
        farT = std::min(farT, std::max(a, b));
    }
    return nearT <= farT;
}
template<size_t N>
Row reference(const std::array<Leaf, N>& scene, const Ray& r) {
    Row result{miss, miss, 0, 0};
    // Brute-force analytic plane intersections in double precision. No
    // packed addresses, BVH traversal, compaction or wave ordering involved.
    for (const auto& leaf : scene) {
        if (r.dz == 0) {
            // A coplanar ray can enter the flat box but never hits the triangle.
            result[2] += r.z == leaf.z && in_plane_box(leaf, r);
            continue;
        }
        const double t = (double(leaf.z) - r.z) / r.dz;
        const double x = r.x + t*r.dx - leaf.x, y = r.y + t*r.dy - leaf.y;
        if (t < r.nearT || t > r.farT || x < 0 || x > 2 || y < 0 || y > 2) continue;
        ++result[2];
        if (!leaf.readable || leaf.degenerate || x+y > 2) continue;
        ++result[3];
        const Word distance = bits(t == 0 ? 0.f : static_cast<float>(t));
        if (distance < result[1] || (distance == result[1] && leaf.id < result[0])) {
            result[0] = leaf.id;
            result[1] = distance;
        }
    }
    return result;
}

using PackedLeaf = std::array<std::uint8_t, 32>;
std::vector<PackedLeaf> encode_leaves(const Scene& scene, Word epoch, bool flipId) {
    std::vector<PackedLeaf> packed(leaves);
    constexpr Word masks[]{0,1,3,7,15,31,63,127,255,511,1023,0xaaaaaaaa,0x55555555,0xffffffff};
    for (Word i = 0; i < leaves; ++i) {
        const auto& leaf = scene[i];
        auto& bytes = packed[i];
        bytes.fill(static_cast<std::uint8_t>(0x95u + i));
        Word header = leaf.id | (static_cast<Word>(leaf.degenerate) << 18);
        if (!leaf.readable) header |= 1u << (i == 31 ? 16 : 17);
        const Word mask = masks[(i + epoch) % std::size(masks)];
        Word first = header ^ ~mask, second = header ^ mask;
        // The witness changes one selected ID bit in the encoded input only.
        if (flipId && epoch == 0 && i == 0) second ^= 1;
        const Word fields[]{bits(leaf.x), bits(leaf.y), bits(leaf.z), first, second, (13*i + epoch*7) % leaves};
        std::memcpy(bytes.data() + (i + epoch) % 4, fields, sizeof(fields));
        std::memcpy(bytes.data() + 28, &mask, sizeof(mask));
    }
    return packed;
}

enum class Inputs { original, faultControls, packed, packedIdFlip };
std::vector<Word> trace_custom(ID3D12Device* device, const std::vector<Ray>& rays, Inputs inputs) {
    const UINT count = static_cast<UINT>(rays.size());
    const UINT frameBytes = count * sizeof(Row);
    const UINT sceneBytes = sceneRows * sizeof(Row);
    const bool packed = inputs == Inputs::packed || inputs == Inputs::packedIdFlip;
    const UINT storageBytes = sceneBytes + (packed ? sizeof(Row) : 0);
    std::vector<Row> rayRows;
    for (const auto& r : rays) {
        rayRows.push_back(pack(r.x, r.y, r.z, bits(r.nearT)));
        rayRows.push_back(pack(r.dx, r.dy, r.dz, bits(r.farT)));
    }
    auto rayInput = upload(device, rayRows);
    constexpr auto writable = D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS;
    auto scene = make_buffer(device, storageBytes, D3D12_HEAP_TYPE_DEFAULT, D3D12_RESOURCE_STATE_COMMON, writable);
    auto output = make_buffer(device, frameBytes, D3D12_HEAP_TYPE_DEFAULT, D3D12_RESOURCE_STATE_COMMON, writable);
    auto back = make_buffer(device, epochs*frameBytes, D3D12_HEAP_TYPE_READBACK, D3D12_RESOURCE_STATE_COPY_DEST);
    std::array<ComPtr<ID3D12Resource>, epochs> sources;
    std::array<ComPtr<ID3D12Resource>, epochs> seeds;
    ComPtr<ID3D12Resource> sceneBack;
    if (packed) sceneBack = make_buffer(device, epochs*storageBytes, D3D12_HEAP_TYPE_READBACK, D3D12_RESOURCE_STATE_COPY_DEST);
    Kernel writer(device, packed ? D3D12_SHADER_BYTECODE{ExpandLeaves, sizeof(ExpandLeaves)} :
                                   D3D12_SHADER_BYTECODE{WriteScene, sizeof(WriteScene)});
    Kernel tracer(device, {TraceHits, sizeof(TraceHits)});
    ComputeCommands commands(device, writer.pipeline.Get());
    auto* list = commands.list.Get();
    auto sceneState = D3D12_RESOURCE_STATE_COMMON;
    for (Word epoch = 0; epoch < epochs; ++epoch) {
        const auto geometry = make_scene(epoch);
        auto rows = serialize(geometry, epoch);
        if (inputs == Inputs::faultControls) {
            // Misroute addresses between the two half-groups, replay stale
            // geometry, or alias an invalid high word into the allocation.
            if (epoch == 0) {
                std::swap(rows[0][3], rows[2*32][3]);
                std::swap(rows[1][3], rows[2*32+1][3]);
            } else if (epoch == 1) {
                rows = serialize(make_scene(0), 0);
            } else {
                --rows[2*31+1][3];
            }
        }
        if (packed) {
            sources[epoch] = upload(device, encode_leaves(geometry, epoch, inputs == Inputs::packedIdFlip));
            // Poison every output field so even an omitted zero write is visible.
            for (auto& row : rows) for (auto& word : row) word = ~word;
            rows.push_back({0xdeadbeef, 0x12345678, 0x543210ab, epoch});
            seeds[epoch] = upload(device, rows);
            transition(list, scene.Get(), sceneState, D3D12_RESOURCE_STATE_COPY_DEST);
            list->CopyBufferRegion(scene.Get(), 0, seeds[epoch].Get(), 0, storageBytes);
            sceneState = D3D12_RESOURCE_STATE_COPY_DEST;
        } else {
            sources[epoch] = upload(device, rows);
        }
        transition(list, scene.Get(), sceneState, D3D12_RESOURCE_STATE_UNORDERED_ACCESS);
        list->SetPipelineState(writer.pipeline.Get());
        list->SetComputeRootSignature(writer.root.Get());
        list->SetComputeRootShaderResourceView(0, sources[epoch]->GetGPUVirtualAddress());
        list->SetComputeRootUnorderedAccessView(1, scene->GetGPUVirtualAddress());
        Row settings{static_cast<Word>(base), static_cast<Word>(base >> 32), sceneBytes, epoch};
        if (packed) list->SetComputeRoot32BitConstants(2, 4, settings.data(), 0);
        list->Dispatch(packed ? leaves/32 : sceneRows/64, 1, 1);
        transition(list, scene.Get(), D3D12_RESOURCE_STATE_UNORDERED_ACCESS, D3D12_RESOURCE_STATE_NON_PIXEL_SHADER_RESOURCE);
        sceneState = D3D12_RESOURCE_STATE_NON_PIXEL_SHADER_RESOURCE;
        transition(list, output.Get(), epoch ? D3D12_RESOURCE_STATE_COPY_SOURCE : D3D12_RESOURCE_STATE_COMMON,
                   D3D12_RESOURCE_STATE_UNORDERED_ACCESS);
        list->SetPipelineState(tracer.pipeline.Get());
        list->SetComputeRootSignature(tracer.root.Get());
        list->SetComputeRootShaderResourceView(0, scene->GetGPUVirtualAddress());
        list->SetComputeRootShaderResourceView(1, rayInput->GetGPUVirtualAddress());
        list->SetComputeRootUnorderedAccessView(2, output->GetGPUVirtualAddress());
        list->SetComputeRoot32BitConstants(3, 4, settings.data(), 0);
        list->Dispatch(count, 1, 1);
        transition(list, output.Get(), D3D12_RESOURCE_STATE_UNORDERED_ACCESS, D3D12_RESOURCE_STATE_COPY_SOURCE);
        list->CopyBufferRegion(back.Get(), epoch*frameBytes, output.Get(), 0, frameBytes);
        if (packed) {
            transition(list, scene.Get(), sceneState, D3D12_RESOURCE_STATE_COPY_SOURCE);
            sceneState = D3D12_RESOURCE_STATE_COPY_SOURCE;
            list->CopyBufferRegion(sceneBack.Get(), epoch*storageBytes, scene.Get(), 0, storageBytes);
        }
    }
    commands.submit_and_wait(device);
    if (packed) {
        const auto actual = read(sceneBack.Get(), epochs * storageBytes / sizeof(Word));
        for (Word epoch = 0; epoch < epochs; ++epoch) {
            auto geometry = make_scene(epoch);
            if (inputs == Inputs::packedIdFlip && epoch == 0) geometry[0].id ^= 1;
            auto expected = serialize(geometry, epoch);
            expected.push_back({0xdeadbeef, 0x12345678, 0x543210ab, epoch});
            for (Word i = 0; i < expected.size(); ++i)
                for (Word field = 0; field < 4; ++field)
                    equal(actual[epoch * storageBytes / sizeof(Word) + 4 * i + field], expected[i][field], i, field);
        }
    }
    return read(back.Get(), epochs*count*4);
}
}

void check_bvh_hits(ID3D12Device* device) {
    const auto rays = make_rays();
    const UINT count = static_cast<UINT>(rays.size());
    const auto result = trace_custom(device, rays, Inputs::original);
    for (Word epoch = 0; epoch < epochs; ++epoch) {
        const auto geometry = make_scene(epoch);
        Word hits = 0;
        for (Word i = 0; i < count; ++i) {
            const auto expected = reference(geometry, rays[i]);
            const Word record = epoch*count+i;
            for (Word field = 0; field < 4; ++field)
                equal(result[4*record+field], expected[field], record, field);
            hits += expected[0] != miss;
        }
        std::printf("epoch=%u rays=%u hits=%u misses=%u mismatches=0\n", epoch, count, hits, count-hits);
    }
}

void check_bvh_packed(ID3D12Device* device) {
    const auto rays = make_rays();
    const auto result = trace_custom(device, rays, Inputs::packed);
    const auto changed = trace_custom(device, rays, Inputs::packedIdFlip);
    Word changedRays = 0;
    for (Word epoch = 0; epoch < epochs; ++epoch) {
        const auto geometry = make_scene(epoch);
        auto edited = geometry;
        if (epoch == 0) edited[0].id ^= 1;
        for (Word i = 0; i < rays.size(); ++i) {
            const auto expected = reference(geometry, rays[i]);
            const auto expectedEdit = reference(edited, rays[i]);
            const Word record = static_cast<Word>(epoch * rays.size() + i);
            for (Word field = 0; field < 4; ++field) {
                equal(result[4*record + field], expected[field], record, field);
                equal(changed[4*record + field], expectedEdit[field], record, field);
            }
            changedRays += result[4*record] != changed[4*record];
        }
    }
    if (result[0] == changed[0]) throw std::runtime_error("Packed ID witness missed the selected field");
    std::printf("packed_epochs=%u scene_words_per_epoch=%u guard_words=4 rays_per_run=%zu changed_ids=%u\n",
                epochs, sceneRows * 4, epochs * rays.size(), changedRays);
}

bool check_bvh_differential(ID3D12Device* device, bool forcePipeline) {
    using dxr_fixture::Backend;
    const auto caps = dxr_fixture::capabilities(device);
    const auto backend = !forcePipeline && caps.supports(Backend::inline_query)
        ? Backend::inline_query : Backend::pipeline;
    if (!caps.supports(backend) || caps.model < D3D_SHADER_MODEL_6_5) {
        // The custom BVH compute shaders still target cs_6_5.
        std::puts("skip: BVH differential requires DXR Tier 1.0 and Shader Model 6.5");
        return false;
    }
    std::vector<Ray> rays;
    // DXR triangles use open distance intervals. Keep the target in the
    // interior of both the interval and the triangle for portable comparisons.
    for (Word i = 0; i < leaves; ++i) {
        const float t = float(1 + i/8);
        rays.push_back({float(4*(i%8))+.5f, .5f, 0, t-.25f, 0,0,1, t+.25f});
    }
    for (Word depth = 1; depth <= 32; ++depth)
        rays.push_back({.5f,.5f,0, depth-.25f, 0,0,1, depth+.25f});
    for (Word column = 0; column < 8; ++column) {
        const float x = float(4*column);
        rays.push_back({x+.5f,.5f,0,0, 0,0,1,40});
        rays.push_back({x+.5f,.5f,40,0, 0,0,-1,40});
        rays.push_back({x+1.5f,1.5f,0,0, 0,0,1,40});
        rays.push_back({x+.25f,.375f,0,0, .03125f,.015625f,1,40});
        rays.push_back({x+.5f,.5f,0,3.25f, 0,0,1,3.75f});
    }
    const auto custom = trace_custom(device, rays, Inputs::original);
    const auto corrupt = trace_custom(device, rays, Inputs::faultControls);
    // Each witness isolates the leaf or column targeted by that fault.
    constexpr Word witnesses[]{0, 1, 31};
    constexpr const char* faults[]{"cross_half_address_swap", "stale_scene", "high_word_alias"};
    for (Word epoch = 0; epoch < epochs; ++epoch) {
        const auto geometry = make_scene(epoch);
        std::vector<dxr_fixture::Vertex> vertices;
        std::vector<Leaf> submitted;
        for (const auto& leaf : geometry) {
            if (!leaf.readable) continue;
            submitted.push_back(leaf);
            vertices.push_back({leaf.x, leaf.y, leaf.z});
            vertices.push_back({leaf.x+2, leaf.y, leaf.z});
            vertices.push_back({leaf.x, leaf.y + (leaf.degenerate ? 0 : 2), leaf.z});
        }
        auto native = dxr_fixture::trace(device, vertices, {dxr_fixture::instance(1, 255)}, rays, backend);
        Word hits = 0, differences = 0;
        bool witnessDetected = false;
        for (size_t i = 0; i < rays.size(); ++i) {
            const auto expected = reference(geometry, rays[i]);
            const Word record = static_cast<Word>(epoch*rays.size()+i);
            const Word* observed = &custom[record*4];
            for (Word k = 0; k < 4; ++k) equal(observed[k], expected[k], record, k);
            const bool hit = observed[0] != miss;
            const Word* dxr = &native[4*i];
            equal(dxr[0], hit, record, 4);
            if (hit) {
                ++hits;
                equal(dxr[1], 1, record, 5);
                equal(dxr[3], observed[1], record, 6);
                // For tied distances DXR can select either coincident leaf.
                // Require its specific primitive to intersect at that distance.
                const auto& selected = submitted.at(dxr[2]);
                const auto selectedHit = reference(std::array<Leaf,1>{selected}, rays[i]);
                equal(selectedHit[0], selected.id, record, 7);
                equal(selectedHit[1], observed[1], record, 8);
            }
            const Word* faulty = &corrupt[record*4];
            // These faults change the hit status or distance; no tie ordering
            // or candidate count is needed to detect them.
            const bool detected = ((faulty[0] != miss) != hit) || faulty[1] != observed[1];
            differences += detected;
            if (i == witnesses[epoch]) witnessDetected = detected;
        }
        if (!witnessDetected) throw std::runtime_error(faults[epoch]);
        std::printf("epoch=%u comparisons=%zu hits=%u misses=%zu fault=%s changed=%u witness=%u\n",
            epoch, rays.size(), hits, rays.size()-hits, faults[epoch], differences, witnesses[epoch]);
    }
    return true;
}
