// Render the repository's 64x64 test triangle offscreen and return raw RGBA bytes.
//
// The draw mirrors the non-reference path of tests/offscreen_check.cpp: the same
// triangle.hlsl vertex/pixel shaders, a 64x64 R8G8B8A8 render target, no vertex
// buffer (SV_VertexID positions), and a fence-waited copy to a readback buffer.
// Mode 1 renders the exact triangle; mode 2 renders the FLIP variant, which mirrors
// X in the vertex shader. The provider compares the readback
// against the CPU pixel rule and publishes the bytes for the cross-runner check.
#include <d3d12.h>
#include <dxgi1_6.h>
#include <wrl/client.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <vector>

#include "triangle_vs.h"
#include "triangle_ps.h"
#include "triangle_vs_flip.h"
#include "triangle_ps_flip.h"

namespace {
using Microsoft::WRL::ComPtr;

constexpr UINT side = 64;

void require(HRESULT hr, const char* operation)
{
    if (FAILED(hr)) {
        std::fprintf(stderr, "%s failed (HRESULT 0x%08lx)\n", operation, static_cast<unsigned long>(hr));
        throw hr;
    }
}

ComPtr<ID3D12Device> create_device()
{
    ComPtr<IDXGIFactory6> factory;
    require(CreateDXGIFactory2(0, IID_PPV_ARGS(&factory)), "CreateDXGIFactory2");
    ComPtr<IDXGIAdapter1> adapter;
    char backend[16]{};
    const auto size = GetEnvironmentVariableA("X2W_SHIM_DRAW_ADAPTER", backend, sizeof(backend));
    if (!size || (size < sizeof(backend) && std::strcmp(backend, "warp") == 0)) {
        require(factory->EnumWarpAdapter(IID_PPV_ARGS(&adapter)), "EnumWarpAdapter");
    } else if (size < sizeof(backend) && std::strcmp(backend, "hardware") == 0) {
        for (UINT i = 0;; ++i) {
            const HRESULT hr = factory->EnumAdapterByGpuPreference(i, DXGI_GPU_PREFERENCE_HIGH_PERFORMANCE,
                                                                   IID_PPV_ARGS(&adapter));
            if (hr == DXGI_ERROR_NOT_FOUND) {
                std::fputs("no D3D12 physical adapter\n", stderr);
                ExitProcess(77);
            }
            require(hr, "EnumAdapterByGpuPreference");
            DXGI_ADAPTER_DESC1 desc{};
            require(adapter->GetDesc1(&desc), "GetDesc1");
            if (!(desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE)) {
                const HRESULT support = D3D12CreateDevice(adapter.Get(), D3D_FEATURE_LEVEL_11_0,
                                                          __uuidof(ID3D12Device), nullptr);
                if (support != DXGI_ERROR_UNSUPPORTED) {
                    require(support, "Probe physical device");
                    break;
                }
            }
            adapter.Reset();
        }
    } else {
        require(E_INVALIDARG, "Select draw adapter");
    }
    ComPtr<ID3D12Device> device;
    require(D3D12CreateDevice(adapter.Get(), D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device)), "D3D12CreateDevice");
    return device;
}
} // namespace

bool shim_draw_gpu(unsigned mode, std::vector<unsigned char>& rgba)
{
    rgba.assign(side * side * 4, 0);
    try {
        auto device = create_device();
        D3D12_ROOT_SIGNATURE_DESC root_desc{};
        root_desc.Flags = D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT;
        ComPtr<ID3DBlob> blob;
        require(D3D12SerializeRootSignature(&root_desc, D3D_ROOT_SIGNATURE_VERSION_1, &blob, nullptr),
                "Serialize draw root signature");
        ComPtr<ID3D12RootSignature> root;
        require(device->CreateRootSignature(0, blob->GetBufferPointer(), blob->GetBufferSize(),
                                            IID_PPV_ARGS(&root)), "Create draw root signature");
        const bool flip = mode == 2;
        D3D12_GRAPHICS_PIPELINE_STATE_DESC pso{};
        pso.pRootSignature = root.Get();
        if (flip) {
            pso.VS = {triangle_vs_flip, sizeof(triangle_vs_flip)};
            pso.PS = {triangle_ps_flip, sizeof(triangle_ps_flip)};
        } else {
            pso.VS = {triangle_vs, sizeof(triangle_vs)};
            pso.PS = {triangle_ps, sizeof(triangle_ps)};
        }
        const D3D12_INPUT_ELEMENT_DESC elements[] = {
            {"SV_Position", 0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0, 0, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0},
            {"COLOR", 0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0, 16, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0},
        };
        pso.InputLayout = {elements, 2};
        pso.RasterizerState.FillMode = D3D12_FILL_MODE_SOLID;
        pso.RasterizerState.CullMode = D3D12_CULL_MODE_NONE;
        auto& blend = pso.BlendState.RenderTarget[0];
        blend.SrcBlend = blend.SrcBlendAlpha = D3D12_BLEND_ONE;
        blend.DestBlend = blend.DestBlendAlpha = D3D12_BLEND_ZERO;
        blend.BlendOp = blend.BlendOpAlpha = D3D12_BLEND_OP_ADD;
        blend.RenderTargetWriteMask = D3D12_COLOR_WRITE_ENABLE_ALL;
        pso.SampleMask = UINT_MAX;
        pso.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
        pso.NumRenderTargets = 1;
        pso.RTVFormats[0] = DXGI_FORMAT_R8G8B8A8_UNORM;
        pso.SampleDesc.Count = 1;
        ComPtr<ID3D12PipelineState> pipeline;
        require(device->CreateGraphicsPipelineState(&pso, IID_PPV_ARGS(&pipeline)), "Create draw pipeline");

        D3D12_RESOURCE_DESC tex{};
        tex.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
        tex.Width = tex.Height = side;
        tex.DepthOrArraySize = tex.MipLevels = 1;
        tex.SampleDesc.Count = 1;
        tex.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        tex.Flags = D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET;
        D3D12_CLEAR_VALUE clear{};
        clear.Format = tex.Format;
        clear.Color[3] = 1;
        D3D12_HEAP_PROPERTIES target_heap{};
        target_heap.Type = D3D12_HEAP_TYPE_DEFAULT;
        target_heap.CreationNodeMask = target_heap.VisibleNodeMask = 1;
        ComPtr<ID3D12Resource> target;
        require(device->CreateCommittedResource(&target_heap, D3D12_HEAP_FLAG_NONE, &tex,
                                                D3D12_RESOURCE_STATE_RENDER_TARGET, &clear,
                                                IID_PPV_ARGS(&target)), "Create draw target");
        D3D12_PLACED_SUBRESOURCE_FOOTPRINT footprint{};
        device->GetCopyableFootprints(&tex, 0, 1, 0, &footprint, nullptr, nullptr, nullptr);
        const UINT64 byte_count = footprint.Offset + UINT64{footprint.Footprint.RowPitch} * side;
        D3D12_RESOURCE_DESC buffer{};
        buffer.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
        buffer.Width = byte_count;
        buffer.Height = buffer.DepthOrArraySize = buffer.MipLevels = buffer.SampleDesc.Count = 1;
        buffer.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
        D3D12_HEAP_PROPERTIES readback_heap{};
        readback_heap.Type = D3D12_HEAP_TYPE_READBACK;
        readback_heap.CreationNodeMask = readback_heap.VisibleNodeMask = 1;
        ComPtr<ID3D12Resource> readback;
        require(device->CreateCommittedResource(&readback_heap, D3D12_HEAP_FLAG_NONE, &buffer,
                                                D3D12_RESOURCE_STATE_COPY_DEST, nullptr,
                                                IID_PPV_ARGS(&readback)), "Create draw readback");
        D3D12_DESCRIPTOR_HEAP_DESC heap_desc{};
        heap_desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
        heap_desc.NumDescriptors = 1;
        ComPtr<ID3D12DescriptorHeap> descriptors;
        require(device->CreateDescriptorHeap(&heap_desc, IID_PPV_ARGS(&descriptors)), "Create draw RTV heap");
        const auto rtv = descriptors->GetCPUDescriptorHandleForHeapStart();
        device->CreateRenderTargetView(target.Get(), nullptr, rtv);

        D3D12_COMMAND_QUEUE_DESC queue_desc{};
        ComPtr<ID3D12CommandQueue> queue;
        require(device->CreateCommandQueue(&queue_desc, IID_PPV_ARGS(&queue)), "Create draw queue");
        ComPtr<ID3D12CommandAllocator> allocator;
        require(device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&allocator)),
                "Create draw allocator");
        ComPtr<ID3D12GraphicsCommandList> list;
        require(device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, allocator.Get(), pipeline.Get(),
                                          IID_PPV_ARGS(&list)), "Create draw command list");
        const D3D12_VIEWPORT viewport{0, 0, side, side, 0, 1};
        const D3D12_RECT scissor{0, 0, side, side};
        list->SetGraphicsRootSignature(root.Get());
        list->RSSetViewports(1, &viewport);
        list->RSSetScissorRects(1, &scissor);
        list->OMSetRenderTargets(1, &rtv, FALSE, nullptr);
        list->ClearRenderTargetView(rtv, clear.Color, 0, nullptr);
        list->IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
        list->DrawInstanced(3, 1, 0, 0);
        D3D12_RESOURCE_BARRIER barrier{};
        barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
        barrier.Transition = {target.Get(), 0, D3D12_RESOURCE_STATE_RENDER_TARGET,
                              D3D12_RESOURCE_STATE_COPY_SOURCE};
        list->ResourceBarrier(1, &barrier);
        D3D12_TEXTURE_COPY_LOCATION src{};
        src.pResource = target.Get();
        src.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
        D3D12_TEXTURE_COPY_LOCATION dst{};
        dst.pResource = readback.Get();
        dst.Type = D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT;
        dst.PlacedFootprint = footprint;
        list->CopyTextureRegion(&dst, 0, 0, 0, &src, nullptr);
        require(list->Close(), "Close draw command list");
        ComPtr<ID3D12Fence> fence;
        require(device->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence)), "Create draw fence");
        ID3D12CommandList* submitted[]{list.Get()};
        queue->ExecuteCommandLists(1, submitted);
        require(queue->Signal(fence.Get(), 1), "Signal draw fence");
        require(fence->SetEventOnCompletion(1, nullptr), "Wait for draw fence");
        require(device->GetDeviceRemovedReason(), "Draw completion");

        void* mapped = nullptr;
        const D3D12_RANGE range{0, static_cast<SIZE_T>(byte_count)};
        require(readback->Map(0, &range, &mapped), "Map draw readback");
        for (UINT y = 0; y < side; ++y) {
            const auto* row = static_cast<const unsigned char*>(mapped) + footprint.Offset +
                              y * footprint.Footprint.RowPitch;
            std::memcpy(rgba.data() + y * side * 4, row, side * 4);
        }
        const D3D12_RANGE no_writes{0, 0};
        readback->Unmap(0, &no_writes);
        return true;
    } catch (HRESULT) {
        return false;
    }
}
