#include <d3d12.h>
#include <d3d12sdklayers.h>
#include <dxgi1_6.h>
#include <wrl/client.h>
#include <cstdio>
#include <cwchar>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <vector>
#include <iterator>
#include <cstring>
#include "triangle_vs.h"
#include "triangle_ps.h"
#include "ffx_provider_loop.h"
#include "desktop_gpu.h"

#ifdef OFFSCREEN_AGILITY_620
extern "C" {
__declspec(dllexport) extern const UINT D3D12SDKVersion = 620;
__declspec(dllexport) const char* D3D12SDKPath = ".\\D3D12\\";
}
#endif

using Microsoft::WRL::ComPtr;
constexpr UINT side = 64;

void check(HRESULT hr, const char* stage)
{
    if (FAILED(hr)) {
        std::fprintf(stderr, "%s failed (HRESULT 0x%08lx)\n", stage, static_cast<unsigned long>(hr));
        throw std::runtime_error(stage);
    }
}

HRESULT check_feature(ID3D12Device* device, D3D12_FEATURE feature, void* data, UINT size)
{
#if defined(OFFSCREEN_AGILITY_620) && defined(__ID3D12Device16_INTERFACE_DEFINED__)
    ComPtr<ID3D12Device16> versioned;
    if (SUCCEEDED(device->QueryInterface(IID_PPV_ARGS(&versioned))))
        return versioned->CheckFeatureSupport1(feature, data, size, D3D12SDKVersion);
#endif
    return device->CheckFeatureSupport(feature, data, size);
}

bool contains_ignoring_case(const wchar_t* text, const wchar_t* part)
{
    const size_t length = std::wcslen(part);
    for (; *text; ++text) {
        if (_wcsnicmp(text, part, length) == 0) return true;
    }
    return false;
}

// Without XBOX2WINDOWS_ADAPTER, the first D3D12 hardware adapter in high-performance order is used.
// With it, the first whose description contains the value, ignoring case, so a PC with several GPUs
// can test each one. A value that matches no adapter is an error, not a skipped test.
ComPtr<IDXGIAdapter1> select_adapter(IDXGIFactory6* factory, bool warp, ComPtr<ID3D12Device>& device
#ifdef OFFSCREEN_AGILITY_620
    , ID3D12DeviceFactory* device_factory
#endif
)
{
    auto create_device = [&](IDXGIAdapter1* candidate) {
#ifdef OFFSCREEN_AGILITY_620
        return device_factory->CreateDevice(candidate, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(device.ReleaseAndGetAddressOf()));
#else
        return D3D12CreateDevice(candidate, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(device.ReleaseAndGetAddressOf()));
#endif
    };
    auto supports_d3d12 = [&](IDXGIAdapter1* candidate) {
#ifdef OFFSCREEN_AGILITY_620
        return SUCCEEDED(device_factory->CreateDevice(candidate, D3D_FEATURE_LEVEL_11_0, __uuidof(ID3D12Device), nullptr));
#else
        return SUCCEEDED(D3D12CreateDevice(candidate, D3D_FEATURE_LEVEL_11_0, __uuidof(ID3D12Device), nullptr));
#endif
    };
    ComPtr<IDXGIAdapter1> adapter;
    if (warp) {
        check(factory->EnumWarpAdapter(IID_PPV_ARGS(&adapter)), "EnumWarpAdapter");
        check(create_device(adapter.Get()), "Create device");
        return adapter;
    }
    wchar_t wanted[128]{};
    const DWORD filter = GetEnvironmentVariableW(L"XBOX2WINDOWS_ADAPTER", wanted, 128);
    if (filter >= 128) throw std::runtime_error("XBOX2WINDOWS_ADAPTER is longer than 127 characters");
    for (UINT index = 0;; ++index) {
        HRESULT hr = factory->EnumAdapterByGpuPreference(index, DXGI_GPU_PREFERENCE_HIGH_PERFORMANCE,
                                                        IID_PPV_ARGS(adapter.ReleaseAndGetAddressOf()));
        if (hr == DXGI_ERROR_NOT_FOUND) {
            if (!filter) return {};
            std::fprintf(stderr, "No D3D12 hardware adapter matches XBOX2WINDOWS_ADAPTER=%ls\n", wanted);
            throw std::runtime_error("Select adapter");
        }
        check(hr, "Enumerate hardware");
        DXGI_ADAPTER_DESC1 desc{};
        check(adapter->GetDesc1(&desc), "Adapter description");
        if (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) continue;
        if (!filter || contains_ignoring_case(desc.Description, wanted)) {
            if (SUCCEEDED(create_device(adapter.Get()))) return adapter;
        } else if (supports_d3d12(adapter.Get())) {
            std::fprintf(stderr, "XBOX2WINDOWS_ADAPTER: skipping %ls\n", desc.Description);
        }
    }
}

ComPtr<ID3D12Resource> resource(ID3D12Device* device, const D3D12_RESOURCE_DESC& desc,
                               D3D12_HEAP_TYPE heap, D3D12_RESOURCE_STATES state,
                               const D3D12_CLEAR_VALUE* clear)
{
    D3D12_HEAP_PROPERTIES props{};
    props.Type = heap;
    props.CreationNodeMask = props.VisibleNodeMask = 1;
    ComPtr<ID3D12Resource> result;
    check(device->CreateCommittedResource(&props, D3D12_HEAP_FLAG_NONE, &desc, state, clear,
                                          IID_PPV_ARGS(&result)), "Create resource");
    return result;
}

void save_bitmap(const char* path, const std::vector<BYTE>& bgra)
{
    BITMAPINFOHEADER info{};
    info.biSize = sizeof(info);
    info.biWidth = side;
    info.biHeight = -static_cast<LONG>(side); // top-down image
    info.biPlanes = 1;
    info.biBitCount = 32;
    BITMAPFILEHEADER header{};
    header.bfType = 0x4d42;
    header.bfOffBits = sizeof(header) + sizeof(info);
    header.bfSize = header.bfOffBits + static_cast<DWORD>(bgra.size());
    std::ofstream file(path, std::ios::binary);
    file.exceptions(std::ios::failbit | std::ios::badbit);
    file.write(reinterpret_cast<const char*>(&header), sizeof(header));
    file.write(reinterpret_cast<const char*>(&info), sizeof(info));
    file.write(reinterpret_cast<const char*>(bgra.data()), bgra.size());
    file.close();
}

std::vector<char> read_shader(const char* path)
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream) throw std::runtime_error("Cannot read reference shader");
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}

void draw(ID3D12Device* device, const char* output, char** reference_shaders)
{
    const bool reference = reference_shaders != nullptr;
    const auto format = reference ? DXGI_FORMAT_B8G8R8A8_UNORM_SRGB : DXGI_FORMAT_R8G8B8A8_UNORM;
    D3D12_ROOT_SIGNATURE_DESC root_desc{};
    if (reference) root_desc.Flags = D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT;
    ComPtr<ID3DBlob> blob;
    check(D3D12SerializeRootSignature(&root_desc, D3D_ROOT_SIGNATURE_VERSION_1, &blob, nullptr),
          "Serialize root signature");
    ComPtr<ID3D12RootSignature> root;
    check(device->CreateRootSignature(0, blob->GetBufferPointer(), blob->GetBufferSize(), IID_PPV_ARGS(&root)),
          "Create root signature");
    D3D12_GRAPHICS_PIPELINE_STATE_DESC pso{};
    pso.pRootSignature = root.Get();
    pso.VS = {triangle_vs, sizeof(triangle_vs)};
    pso.PS = {triangle_ps, sizeof(triangle_ps)};
    std::vector<char> vs, ps;
    const D3D12_INPUT_ELEMENT_DESC elements[] = {
        {"SV_Position", 0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0, 0, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0},
        {"COLOR", 0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0, 16, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0}
    };
    if (reference) {
        vs = read_shader(reference_shaders[0]);
        ps = read_shader(reference_shaders[1]);
        ComPtr<ID3D12RootSignatureDeserializer> embedded, absent;
        HRESULT found = D3D12CreateRootSignatureDeserializer(vs.data(), vs.size(), IID_PPV_ARGS(&embedded));
        HRESULT missing = D3D12CreateRootSignatureDeserializer(triangle_vs, sizeof(triangle_vs), IID_PPV_ARGS(&absent));
        std::printf("desktop_blob_embedded=0x%08lx desktop_blob_no_signature=0x%08lx\n",
                    static_cast<unsigned long>(found), static_cast<unsigned long>(missing));
        check(found, "Read signature from complete reference shader");
        if (!embedded.Get() || SUCCEEDED(missing) || absent.Get())
            throw std::runtime_error("Unexpected embedded-signature result");
        pso.VS = {vs.data(), vs.size()};
        pso.PS = {ps.data(), ps.size()};
        pso.InputLayout = {elements, 2};
    }
    pso.RasterizerState.FillMode = D3D12_FILL_MODE_SOLID;
    pso.RasterizerState.CullMode = D3D12_CULL_MODE_NONE;
    pso.RasterizerState.DepthClipEnable = TRUE;
    auto& blend = pso.BlendState.RenderTarget[0];
    blend.SrcBlend = blend.SrcBlendAlpha = D3D12_BLEND_ONE;
    blend.DestBlend = blend.DestBlendAlpha = D3D12_BLEND_ZERO;
    blend.BlendOp = blend.BlendOpAlpha = D3D12_BLEND_OP_ADD;
    blend.LogicOp = D3D12_LOGIC_OP_NOOP;
    blend.RenderTargetWriteMask = D3D12_COLOR_WRITE_ENABLE_ALL;
    pso.SampleMask = UINT_MAX;
    pso.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
    pso.NumRenderTargets = 1;
    pso.RTVFormats[0] = format;
    pso.SampleDesc.Count = 1;
    ComPtr<ID3D12PipelineState> pipeline;
    check(device->CreateGraphicsPipelineState(&pso, IID_PPV_ARGS(&pipeline)), "Create graphics pipeline");

    D3D12_RESOURCE_DESC tex{};
    tex.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
    tex.Width = tex.Height = side;
    tex.DepthOrArraySize = tex.MipLevels = 1;
    tex.SampleDesc.Count = 1;
    tex.Format = format;
    tex.Flags = D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET;
    D3D12_CLEAR_VALUE clear{};
    clear.Format = format;
    clear.Color[3] = 1;
    if (reference) clear.Color[0] = clear.Color[1] = clear.Color[2] = 0.052860655f;
    auto target = resource(device, tex, D3D12_HEAP_TYPE_DEFAULT, D3D12_RESOURCE_STATE_RENDER_TARGET, &clear);
    D3D12_PLACED_SUBRESOURCE_FOOTPRINT footprint{};
    device->GetCopyableFootprints(&tex, 0, 1, 0, &footprint, nullptr, nullptr, nullptr);
    // Exercise a padded staging layout even when the texture width is already aligned.
    footprint.Footprint.RowPitch += D3D12_TEXTURE_DATA_PITCH_ALIGNMENT;
    const UINT64 byte_count = footprint.Offset + UINT64{footprint.Footprint.RowPitch} * side;
    D3D12_RESOURCE_DESC buffer{};
    buffer.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    buffer.Width = byte_count;
    buffer.Height = buffer.DepthOrArraySize = buffer.MipLevels = buffer.SampleDesc.Count = 1;
    buffer.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    auto readback = resource(device, buffer, D3D12_HEAP_TYPE_READBACK, D3D12_RESOURCE_STATE_COPY_DEST);
    D3D12_DESCRIPTOR_HEAP_DESC heap_desc{};
    heap_desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
    heap_desc.NumDescriptors = 1;
    ComPtr<ID3D12DescriptorHeap> descriptors;
    check(device->CreateDescriptorHeap(&heap_desc, IID_PPV_ARGS(&descriptors)), "Create RTV heap");
    const auto rtv = descriptors->GetCPUDescriptorHandleForHeapStart();
    device->CreateRenderTargetView(target.Get(), nullptr, rtv);

    D3D12_COMMAND_QUEUE_DESC queue_desc{};
    ComPtr<ID3D12CommandQueue> queue;
    check(device->CreateCommandQueue(&queue_desc, IID_PPV_ARGS(&queue)), "Create queue");
    ComPtr<ID3D12CommandAllocator> allocator;
    check(device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&allocator)), "Create allocator");
    ComPtr<ID3D12GraphicsCommandList> list;
    check(device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, allocator.Get(), pipeline.Get(),
                                    IID_PPV_ARGS(&list)), "Create command list");
    const D3D12_VIEWPORT viewport{0, 0, side, side, 0, 1};
    const D3D12_RECT scissor{0, 0, side, side};
    list->SetGraphicsRootSignature(root.Get());
    list->RSSetViewports(1, &viewport);
    list->RSSetScissorRects(1, &scissor);
    list->OMSetRenderTargets(1, &rtv, FALSE, nullptr);
    list->ClearRenderTargetView(rtv, clear.Color, 0, nullptr);
    list->IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    ComPtr<ID3D12Resource> vertex_buffer;
    if (reference) {
        // Positions and linear RGBA from Microsoft's pinned SimpleTriangle sample.
        constexpr float vertices[][8] = {
            {0, .5f, .5f, 1, 1, 0, 0, 1}, {.5f, -.5f, .5f, 1, 0, 1, 0, 1},
            {-.5f, -.5f, .5f, 1, 0, 0, 1, 1}
        };
        auto vertex_desc = buffer;
        vertex_desc.Width = sizeof(vertices);
        vertex_buffer = resource(device, vertex_desc, D3D12_HEAP_TYPE_UPLOAD, D3D12_RESOURCE_STATE_GENERIC_READ);
        void* mapped_vertices = nullptr;
        const D3D12_RANGE empty{};
        check(vertex_buffer->Map(0, &empty, &mapped_vertices), "Map reference vertices");
        std::memcpy(mapped_vertices, vertices, sizeof(vertices));
        vertex_buffer->Unmap(0, nullptr);
        const D3D12_VERTEX_BUFFER_VIEW view{
            vertex_buffer->GetGPUVirtualAddress(), sizeof(vertices), sizeof(vertices[0])};
        list->IASetVertexBuffers(0, 1, &view);
    }
    list->DrawInstanced(3, 1, 0, 0);
    D3D12_RESOURCE_BARRIER barrier{};
    barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    barrier.Transition = {target.Get(), 0, D3D12_RESOURCE_STATE_RENDER_TARGET, D3D12_RESOURCE_STATE_COPY_SOURCE};
    list->ResourceBarrier(1, &barrier);
    D3D12_TEXTURE_COPY_LOCATION src{};
    src.pResource = target.Get();
    src.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
    D3D12_TEXTURE_COPY_LOCATION dst{};
    dst.pResource = readback.Get();
    dst.Type = D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT;
    dst.PlacedFootprint = footprint;
    list->CopyTextureRegion(&dst, 0, 0, 0, &src, nullptr);
    check(list->Close(), "Close command list");
    ComPtr<ID3D12Fence> fence;
    check(device->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence)), "Create fence");
    ID3D12CommandList* submitted[]{list.Get()};
    queue->ExecuteCommandLists(1, submitted);
    check(queue->Signal(fence.Get(), 1), "Signal GPU fence");
    check(fence->SetEventOnCompletion(1, nullptr), "Wait for GPU");
    check(device->GetDeviceRemovedReason(), "GPU completion");

    std::vector<BYTE> bgra(side * side * 4);
    void* mapped = nullptr;
    D3D12_RANGE range{0, static_cast<SIZE_T>(byte_count)};
    check(readback->Map(0, &range, &mapped), "Map pixel readback");
    unsigned mismatches = 0;
    for (UINT y = 0; y < side; ++y) {
        const BYTE* row = static_cast<const BYTE*>(mapped) + footprint.Offset + y * footprint.Footprint.RowPitch;
        for (UINT x = 0; x < side; ++x) {
            const BYTE* rgba = row + x * 4;
            auto* pixel = &bgra[(y * side + x) * 4];
            if (reference) {
                std::memcpy(pixel, rgba, 4); // Reference target already uses BGRA.
                continue;
            }
            const bool inside = x >= 8 && y >= 8 && x + y <= 63;
            if (rgba[0] != 0 || rgba[1] != (inside ? 255 : 0) || rgba[2] != 0 || rgba[3] != 255) {
                ++mismatches;
            }
            pixel[0] = rgba[2];
            pixel[1] = rgba[1];
            pixel[2] = rgba[0];
            pixel[3] = rgba[3];
        }
    }
    const D3D12_RANGE no_writes{0, 0};
    readback->Unmap(0, &no_writes);
    std::printf("pixels=%u row_pitch=%u\n", side * side, footprint.Footprint.RowPitch);
    if (!reference) std::printf("mismatches=%u\n", mismatches);
    save_bitmap(output, bgra);
    if (mismatches) throw std::runtime_error("GPU pixels differ from CPU reference");
}

bool report_debug_errors(ID3D12InfoQueue* messages)
{
    if (!messages) return false;
    unsigned errors = 0;
    unsigned warnings = 0;
    const auto count = messages->GetNumStoredMessagesAllowedByRetrievalFilter();
    for (UINT64 i = 0; i < count; ++i) {
        SIZE_T bytes = 0;
        check(messages->GetMessage(i, nullptr, &bytes), "Read debug message size");
        std::vector<BYTE> storage(bytes);
        auto* msg = reinterpret_cast<D3D12_MESSAGE*>(storage.data());
        check(messages->GetMessage(i, msg, &bytes), "Read debug message");
        if (msg->Severity <= D3D12_MESSAGE_SEVERITY_WARNING) {
            std::fprintf(stderr, "D3D12 %d: %s\n", msg->ID, msg->pDescription);
            if (msg->Severity == D3D12_MESSAGE_SEVERITY_WARNING) ++warnings;
            else ++errors;
        }
    }
    std::printf("debug_errors=%u debug_warnings=%u\n", errors, warnings);
    return errors != 0;
}

// These operations create pipelines from cs_6_5 fixtures. An adapter below SM 6.5, such as the
// Windows 10 in-box WARP (SM 6.2), rejects them at pipeline creation with E_INVALIDARG.
bool needs_cs_6_5(std::string_view operation)
{
    return operation == "--bvh-reads" || operation == "--bvh-waves" ||
           operation == "--bvh-hits" || operation == "--bvh-packed" || operation == "--bvh-numeric" ||
           operation == "--bvh-atomics";
}

bool supports_cs_6_5(ID3D12Device* device)
{
    D3D12_FEATURE_DATA_SHADER_MODEL model{D3D_SHADER_MODEL_6_5};
    check(check_feature(device, D3D12_FEATURE_SHADER_MODEL, &model, sizeof(model)), "Query fixture shader model");
    std::printf("shader_model_capped_at_6_5=0x%x\n", model.HighestShaderModel);
    return model.HighestShaderModel >= D3D_SHADER_MODEL_6_5;
}

int main(int argc, char** argv)
{
    if (argc < 3) return 2;
    const std::string_view operation = argv[2];
    if (operation == "--check-pixel-batch") {
        if (argc < 5) return 2;
    } else if (operation == "--compute-to-pixel") {
        if (argc != 6 && argc != 7) return 2;
    } else if (operation == "--compute-mesh-texture") {
        if (argc != 7 && argc != 8 && (argc != 9 || std::string_view(argv[8]) != "--stale")) return 2;
    } else if (operation == "--check-pixel-quad-lod") {
        if (argc != 4) return 2;
    } else if (operation == "--mesh-entry" || operation == "--mesh-indexed" || operation == "--mesh-textured") {
        if (argc != 6 && !(operation == "--mesh-entry" && argc == 7 &&
            (std::string_view(argv[6]) == "ab" || std::string_view(argv[6]) == "ba"))) return 2;
    } else if (operation == "--mesh-entry-table") {
        if (argc != 6 && (argc != 7 || std::string_view(argv[6]) != "--swap")) return 2;
    } else if (operation == "--mesh-depth-pair") {
        if (argc != 6) return 2;
    } else if (operation == "--check-bc7-tail") {
        if (argc < 6) return 2;
    } else if ((operation == "--depth-mask" || operation == "--depth-mask-swapped")) {
        if (argc != 6) return 2;
    } else if (operation == "--compute-root-file" || operation == "--ffx-immediate-conversion" ||
               operation == "--spirv-address-window" || operation == "--spirv-sampler-views") {
        if (argc != 4) return 2;
    } else {
        if (argc != 3 && argc != 5 && argc != 6) return 2;
        if (argc == 6 && operation != "--check-bc7" && operation != "--check-bc7-mip1") return 2;
    }
    if ((operation == "--check-bc7" && argc < 5) || (operation == "--check-bc7-mip1" && argc != 6)) return 2;
    const std::string_view mode = argv[1];
    if (mode != "warp" && mode != "hardware") return 2;
    ComPtr<ID3D12InfoQueue> messages;
    try {
        ComPtr<ID3D12Debug> debug;
#ifdef OFFSCREEN_AGILITY_620
        ComPtr<ID3D12DeviceFactory> device_factory;
        check(D3D12GetInterface(CLSID_D3D12DeviceFactory, IID_PPV_ARGS(&device_factory)), "Load device factory");
        // Without Graphics Tools (for example on a default Windows 10 install) the debug layer reports
        // DXGI_ERROR_SDK_COMPONENT_MISSING even with the SDK layers app-local. The runtime itself still
        // loads, so continue without the layer and report it as unavailable. Other failures stay fatal.
        const HRESULT debug_hr = device_factory->GetConfigurationInterface(CLSID_D3D12Debug, IID_PPV_ARGS(&debug));
        if (debug_hr != DXGI_ERROR_SDK_COMPONENT_MISSING) check(debug_hr, "Load app-local debug layer");
#else
        D3D12GetDebugInterface(IID_PPV_ARGS(&debug));
#endif
        if (debug) debug->EnableDebugLayer();
        std::printf("backend=%s debug_layer=%s\n", argv[1], debug ? "enabled" : "unavailable");
        ComPtr<IDXGIFactory6> factory;
        check(CreateDXGIFactory2(0, IID_PPV_ARGS(&factory)), "Create DXGI factory");
        ComPtr<ID3D12Device> device;
#ifdef OFFSCREEN_AGILITY_620
        auto adapter = select_adapter(factory.Get(), mode == "warp", device, device_factory.Get());
#else
        auto adapter = select_adapter(factory.Get(), mode == "warp", device);
#endif
        if (!adapter) {
            std::puts("No D3D12-capable hardware adapter visible");
            return 77;
        }
        DXGI_ADAPTER_DESC1 desc{};
        check(adapter->GetDesc1(&desc), "Read DXGI adapter");
        LARGE_INTEGER driver{};
        std::printf("adapter=%ls vendor=%04x device=%04x\n", desc.Description, desc.VendorId, desc.DeviceId);
        if (SUCCEEDED(adapter->CheckInterfaceSupport(__uuidof(IDXGIDevice), &driver))) {
            std::printf("driver=%u.%u.%u.%u\n", HIWORD(driver.HighPart), LOWORD(driver.HighPart),
                        HIWORD(driver.LowPart), LOWORD(driver.LowPart));
        } else {
            std::puts("driver=unavailable via DXGI");
        }
        if (debug) check(device.As(&messages), "Read debug queue");
        if (operation == "--check-pixel-batch") {
            bool failed = false;
            for (int i = 4; i < argc; ++i) {
                const char* status = "pass";
                std::fprintf(stderr, "case=%d path=%s\n", i - 4, argv[i]);
                try {
                    check(device->GetDeviceRemovedReason(), "Pixel batch device");
                    check_translated_pixel(device.Get(), argv[3], false, argv[i]);
                } catch (const PixelMismatch& e) {
                    std::fprintf(stderr, "%s\n", e.what());
                    status = "mismatch";
                } catch (const std::exception& e) {
                    std::fprintf(stderr, "%s\n", e.what());
                    status = "error";
                }
                if (report_debug_errors(messages.Get()) || FAILED(device->GetDeviceRemovedReason()))
                    status = "error";
                if (messages) messages->ClearStoredMessages();
                std::printf("case=%d status=%s\n", i - 4, status);
                failed |= std::string_view(status) != "pass";
            }
            return failed ? 1 : 0;
        }
        if (argc == 3 && needs_cs_6_5(operation) && !supports_cs_6_5(device.Get())) return 77;
        if (argc == 3 && (operation == "--compute-root" || operation == "--compute-tables")) {
            check_compute(device.Get(), operation == "--compute-tables");
        } else if (operation == "--spirv-sampler-views") {
            D3D12_FEATURE_DATA_SHADER_MODEL model{D3D_SHADER_MODEL_6_6};
            auto hr = check_feature(device.Get(), D3D12_FEATURE_SHADER_MODEL, &model, sizeof(model));
            if (hr != E_INVALIDARG) check(hr, "Query sampler fixture shader model");
            if (hr == E_INVALIDARG || model.HighestShaderModel < D3D_SHADER_MODEL_6_6) {
                std::puts("skip: sampler fixture requires SM 6.6");
                return 77;
            }
            check_sampler_views(device.Get(), argv[3]);
        } else if (operation == "--spirv-address-window") {
            D3D12_FEATURE_DATA_D3D12_OPTIONS1 options{};
            check(check_feature(device.Get(), D3D12_FEATURE_D3D12_OPTIONS1, &options, sizeof(options)),
                  "Query 64-bit shader integer support");
            D3D12_FEATURE_DATA_SHADER_MODEL model{D3D_SHADER_MODEL_6_6};
            auto model_hr = check_feature(device.Get(), D3D12_FEATURE_SHADER_MODEL, &model, sizeof(model));
            if (model_hr != E_INVALIDARG) check(model_hr, "Query address-window shader model");
            if (!options.Int64ShaderOps || model_hr == E_INVALIDARG || model.HighestShaderModel < D3D_SHADER_MODEL_6_6) {
                std::puts("skip: address window fixture requires SM 6.6 and 64-bit shader integer operations");
                return 77;
            }
            check_spirv_window(device.Get(), argv[3]);
        } else if (argc == 4 && (operation == "--compute-root-file" || operation == "--ffx-immediate-conversion")) {
            check_compute_file(device.Get(), argv[3], operation == "--ffx-immediate-conversion");
        } else if (argc == 5 && operation == "--compute-store-case") {
            check_compute_file(device.Get(), argv[3], false, argv[4]);
        } else if (argc == 3 && operation == "--ffx-device-init") {
            check_ffx_device_init(device.Get());
        } else if (argc == 3 && operation == "--ffx-provider-loop") {
            check_ffx_provider_loop(device.Get());
        } else if (argc == 3 && operation == "--ffx-recurrent") {
            check_ffx_recurrent(device.Get());
        } else if (operation == "--check-bc7-tail") {
            check_bc7_tail(device.Get(), argv[3], argv[4], argc - 5, argv + 5);
        } else if (argc == 6 && operation == "--check-bc7-mip1") {
            check_bc7_pixel(device.Get(), argv[3], argv[4], nullptr, argv[5]);
        } else if ((argc == 5 || argc == 6) && operation == "--check-bc7") {
            check_bc7_pixel(device.Get(), argv[3], argv[4], argc == 6 ? argv[5] : nullptr);
        } else if (argc == 5 && (operation == "--dual-pixel" || operation == "--dual-pixel-swapped")) {
            check_dual_pixel(device.Get(), argv[3], argv[4], operation == "--dual-pixel-swapped");
        } else if (argc == 5 && operation == "--sampled-coverage") {
            check_sampled_coverage(device.Get(), argv[3], argv[4]);
        } else if (argc == 5 && operation == "--check-pixel-case") {
            check_translated_pixel(device.Get(), argv[3], false, argv[4]);
        } else if (operation == "--compute-to-pixel") {
            check_compute_to_pixel(device.Get(), argv[3], argv[4], argv[5], argc == 7 ? argv[6] : nullptr);
        } else if (argc == 5 && (operation == "--check-pixel-attribute" || operation == "--check-pixel-attribute-rg")) {
            check_attribute_pixel(device.Get(), argv[3], argv[4], operation == "--check-pixel-attribute-rg");
        } else if (argc == 5 && operation == "--check-pixel-case-rg") {
            check_translated_pixel(device.Get(), argv[3], false, argv[4],
                                   D3D12_COLOR_WRITE_ENABLE_RED | D3D12_COLOR_WRITE_ENABLE_GREEN);
        } else if (operation == "--check-pixel-quad-lod") {
            check_pixel_quad_lod(device.Get(), argv[3]);
        } else if (operation == "--check-pixel") {
            if (argc != 5 || (std::string_view(argv[4]) != "rgba" && std::string_view(argv[4]) != "bgra"))
                throw std::runtime_error("Expected --check-pixel <pixel.cso> rgba|bgra");
            check_translated_pixel(device.Get(), argv[3], std::string_view(argv[4]) == "bgra");
        } else if ((operation == "--depth-mask" || operation == "--depth-mask-swapped")) {
            check_depth_mask_draw(device.Get(), argv[3], argv[4], argv[5], operation == "--depth-mask-swapped");
        } else if (argc == 3 && operation == "--dual-uav") {
            check_dual_uav(device.Get());
        } else if (argc == 3 && operation == "--texture-mips") {
            check_texture_mips(device.Get());
        } else if (argc == 3 && operation == "--bvh-root-roundtrip") {
            check_bvh_root_roundtrip(device.Get());
        } else if (argc == 3 && (operation == "--bvh-differential" || operation == "--bvh-differential-pipeline")) {
            if (!check_bvh_differential(device.Get(), operation == "--bvh-differential-pipeline")) return 77;
        } else if (argc == 3 && operation == "--bvh-hits") {
            check_bvh_hits(device.Get());
        } else if (argc == 3 && operation == "--dxr-update") {
            if (!check_dxr_update(device.Get())) return 77;
        } else if (operation == "--mesh-entry" || operation == "--mesh-indexed") {
            auto binding = MeshConstantBinding::root;
            if (argc == 7)
                binding = argv[6][0] == 'b' ? MeshConstantBinding::swapped_root_pair : MeshConstantBinding::root_pair;
            if (!check_mesh_entry_draw(device.Get(), argv[3], argv[4], argv[5],
                                       operation == "--mesh-indexed", binding)) return 77;
        } else if (operation == "--mesh-entry-table") {
            const auto binding = argc == 7 ? MeshConstantBinding::swapped_table : MeshConstantBinding::table;
            if (!check_mesh_entry_draw(device.Get(), argv[3], argv[4], argv[5], false, binding)) return 77;
        } else if (operation == "--mesh-textured") {
            if (!check_mesh_entry_draw(device.Get(), argv[3], argv[4], argv[5],
                                       true, MeshConstantBinding::root, MeshDrawMode::textured)) return 77;
        } else if (operation == "--compute-mesh-texture") {
            const MeshTextureProducers producers{argv[6], argc >= 8 ? argv[7] : nullptr, argc == 9};
            if (!check_mesh_entry_draw(device.Get(), argv[3], argv[4], argv[5],
                                       true, MeshConstantBinding::root, MeshDrawMode::textured, &producers)) return 77;
        } else if (operation == "--mesh-depth-pair") {
            if (!check_mesh_entry_draw(device.Get(), argv[3], argv[4], argv[5],
                                       true, MeshConstantBinding::root, MeshDrawMode::depth_pair)) return 77;
        } else if (argc == 3 && operation == "--dxr-facing") {
            if (!check_dxr_facing(device.Get())) return 77;
        } else if (argc == 3 && operation == "--dxr-opacity") {
            if (!check_dxr_opacity(device.Get(), mode == "warp")) return 77;
        } else if (argc == 3 && operation == "--bvh-packed") {
            check_bvh_packed(device.Get());
        } else if (argc == 3 && operation == "--bvh-numeric") {
            check_bvh_numeric(device.Get());
        } else if (argc == 3 && operation == "--bvh-atomics") {
            check_bvh_atomics(device.Get());
        } else if (argc == 3 && operation == "--bvh-reads") {
            check_bvh_reads(device.Get());
        } else if (argc == 3 && (operation == "--bvh-waves" || operation == "--bvh-wave64")) {
            if (!check_bvh_waves(device.Get(), operation == "--bvh-wave64")) return 77;
        } else if (argc == 3 && operation == "--gpu-alias") {
            if (!check_gpu_alias(device.Get())) return 77;
        } else if (argc == 3 && operation == "--gpu-alias-lookup") {
            if (!check_gpu_alias_lookup(device.Get())) return 77;
        } else if (argc == 3 && operation == "--gpu-alias-lookup-writes") {
            if (!check_gpu_alias_lookup_writes(device.Get())) return 77;
        } else if (argc == 3 && operation == "--gpu-alias-registry") {
            if (!check_gpu_alias_registry(device.Get())) return 77;
        } else if (argc == 3 && operation == "--buffer-ops") {
            D3D12_FEATURE_DATA_SHADER_MODEL model{D3D_SHADER_MODEL_6_0};
            const HRESULT hr = check_feature(device.Get(), D3D12_FEATURE_SHADER_MODEL, &model, sizeof(model));
            if (hr != E_INVALIDARG) check(hr, "Query buffer operation shader model");
            if (hr == E_INVALIDARG || model.HighestShaderModel < D3D_SHADER_MODEL_6_0) {
                std::puts("Buffer operations require Shader Model 6.0");
                return 77;
            }
            std::printf("shader_model_capped_at_6_0=0x%x\n", model.HighestShaderModel);
            check_buffer_ops(device.Get());
        } else if (argc == 3 && (operation == "--ray-query" || operation == "--dxr-pipeline")) {
            if (!check_dxr_rays(device.Get(), operation == "--dxr-pipeline")) return 77;
        } else if (argc == 3 && operation == "--wave-shuffle") {
            if (!check_wave_shuffle(device.Get())) return 77;
        } else if (operation.substr(0, 2) == "--") {
            std::fprintf(stderr, "Unknown GPU operation or invalid arguments: %s\n", argv[2]);
            return 2;
        } else {
            draw(device.Get(), argv[2], argc == 5 ? argv + 3 : nullptr);
        }
        return report_debug_errors(messages.Get()) ? 1 : 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s\n", e.what());
        report_debug_errors(messages.Get());
        return 1;
    }
}
