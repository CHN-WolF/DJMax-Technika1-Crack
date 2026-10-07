// audio_peak.c — poll the default render endpoint's peak meter (detect audio output)
// usage: audio_peak [seconds]
#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <endpointvolume.h>
#include <stdio.h>

// mingw-w64 的 endpointvolume.h 不带 IID 定义,手工给:
static const GUID MY_IID_IAudioMeterInformation =
    { 0xC02216F6, 0x8C67, 0x4B5B, { 0x9D, 0x00, 0xD0, 0x08, 0xE7, 0x3E, 0x39, 0x33 } };
static const GUID MY_CLSID_MMDeviceEnumerator =
    { 0xBCDE0395, 0xE52F, 0x467C, { 0x8E, 0x3D, 0xC4, 0x57, 0x92, 0x91, 0x69, 0x2E } };
static const GUID MY_IID_IMMDeviceEnumerator =
    { 0xA95664D2, 0x9614, 0x4F35, { 0xA7, 0x46, 0xDE, 0x8D, 0xB6, 0x36, 0x17, 0xE6 } };

// IAudioMeterInformation minimal declaration (this toolchain's endpointvolume.h
// only forward-declares it)
typedef struct MyAudioMeterInformationVtbl {
    void* QueryInterface; void* AddRef; void* Release;
    HRESULT (__stdcall* GetPeakValue)(void* self, float* peak);
    void* GetMeteringChannelCount;
    void* GetChannelsPeakValues;
} MyAudioMeterInformationVtbl;
typedef struct { MyAudioMeterInformationVtbl* lpVtbl; } MyAudioMeterInformation;

int main(int argc, char** argv) {
    int secs = argc > 1 ? atoi(argv[1]) : 10;
    CoInitialize(0);
    IMMDeviceEnumerator* pEnum = 0;
    HRESULT hr = CoCreateInstance(&MY_CLSID_MMDeviceEnumerator, 0, CLSCTX_ALL,
                                  &MY_IID_IMMDeviceEnumerator, (void**)&pEnum);
    if (FAILED(hr)) { printf("enum fail %08lx\n", hr); return 1; }
    IMMDevice* pDev = 0;
    IMMDeviceCollection* pColl = 0;
    hr = pEnum->lpVtbl->EnumAudioEndpoints(pEnum, eRender, DEVICE_STATE_ACTIVE, &pColl);
    MyAudioMeterInformation* pMeter = 0;
    if (SUCCEEDED(hr) && pColl) {
        UINT cnt = 0;
        pColl->lpVtbl->GetCount(pColl, &cnt);
        for (UINT i = 0; i < cnt && !pMeter; i++) {
            IMMDevice* d = 0;
            if (SUCCEEDED(pColl->lpVtbl->Item(pColl, i, &d)) && d) {
                if (FAILED(d->lpVtbl->Activate(d, &MY_IID_IAudioMeterInformation, CLSCTX_ALL, 0, (void**)&pMeter)))
                    d->lpVtbl->Release(d);
                else { pDev = d; printf("meter on endpoint #%u\n", i); }
            }
        }
    }
    if (!pMeter) { printf("no meter interface on any render endpoint\n"); return 1; }
    float maxpeak = 0;
    for (int i = 0; i < secs * 5; i++) {
        float peak = 0;
        pMeter->lpVtbl->GetPeakValue(pMeter, &peak);
        if (peak > maxpeak) maxpeak = peak;
        printf("peak=%.3f%s\n", peak, peak > 0.001f ? "  <-- SOUND" : "");
        Sleep(200);
    }
    printf("MAX PEAK: %.4f %s\n", maxpeak, maxpeak > 0.001f ? "(audio active)" : "(silent)");
    return 0;
}
