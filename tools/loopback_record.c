// loopback_record.c — WASAPI loopback recorder: records the PC's final audio
// output (what the speakers play) to a WAV file. Usage: loopback_record out.wav [seconds]
#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <stdio.h>

static const GUID MY_CLSID_MMDeviceEnumerator =
    { 0xBCDE0395, 0xE52F, 0x467C, { 0x8E, 0x3D, 0xC4, 0x57, 0x92, 0x91, 0x69, 0x2E } };
static const GUID MY_IID_IMMDeviceEnumerator =
    { 0xA95664D2, 0x9614, 0x4F35, { 0xA7, 0x46, 0xDE, 0x8D, 0xB6, 0x36, 0x17, 0xE6 } };
static const GUID MY_IID_IAudioClient =
    { 0x1CB9AD4C, 0xDBFA, 0x4c32, { 0xB1, 0x78, 0xC2, 0xF5, 0x68, 0xA7, 0x03, 0xB2 } };
static const GUID MY_IID_IAudioCaptureClient =
    { 0xC8ADBD64, 0xE71E, 0x48a0, { 0xA4, 0xDE, 0x18, 0x5C, 0x39, 0x5C, 0xD3, 0x17 } };

static void wav_header(FILE* f, DWORD bytes, WORD ch, DWORD rate, WORD bits) {
    fwrite("RIFF", 1, 4, f);
    DWORD sz = bytes + 36; fwrite(&sz, 4, 1, f);
    fwrite("WAVEfmt ", 1, 8, f);
    DWORD fmtlen = 16; fwrite(&fmtlen, 4, 1, f);
    WORD tag = 1; fwrite(&tag, 2, 1, f);
    fwrite(&ch, 2, 1, f);
    fwrite(&rate, 4, 1, f);
    DWORD bps = rate * ch * (bits / 8); fwrite(&bps, 4, 1, f);
    WORD align = ch * (bits / 8); fwrite(&align, 2, 1, f);
    fwrite(&bits, 2, 1, f);
    fwrite("data", 1, 4, f);
    fwrite(&bytes, 4, 1, f);
}

int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: loopback_record out.wav [seconds]\n"); return 2; }
    int secs = argc > 2 ? atoi(argv[2]) : 30;
    CoInitialize(0);
    IMMDeviceEnumerator* pEnum = 0;
    HRESULT hr = CoCreateInstance(&MY_CLSID_MMDeviceEnumerator, 0, CLSCTX_ALL,
                                  &MY_IID_IMMDeviceEnumerator, (void**)&pEnum);
    if (FAILED(hr)) { printf("enum fail %08lx\n", hr); return 1; }
    IMMDevice* pDev = 0;
    hr = pEnum->lpVtbl->GetDefaultAudioEndpoint(pEnum, eRender, eConsole, &pDev);
    if (FAILED(hr)) { printf("endpoint fail %08lx\n", hr); return 1; }
    IAudioClient* pAC = 0;
    hr = pDev->lpVtbl->Activate(pDev, &MY_IID_IAudioClient, CLSCTX_ALL, 0, (void**)&pAC);
    if (FAILED(hr)) { printf("activate fail %08lx\n", hr); return 1; }
    WAVEFORMATEX* wfx = 0;
    hr = pAC->lpVtbl->GetMixFormat(pAC, &wfx);
    if (FAILED(hr)) { printf("mixfmt fail\n"); return 1; }
    printf("mix format: %lu Hz, %u ch, tag=%u bits=%u\n",
           wfx->nSamplesPerSec, wfx->nChannels, wfx->wFormatTag, wfx->wBitsPerSample);
    hr = pAC->lpVtbl->Initialize(pAC, AUDCLNT_SHAREMODE_SHARED,
                                 AUDCLNT_STREAMFLAGS_LOOPBACK, 0, 0, wfx, 0);
    if (FAILED(hr)) { printf("init fail %08lx\n", hr); return 1; }
    IAudioCaptureClient* pCap = 0;
    hr = pAC->lpVtbl->GetService(pAC, &MY_IID_IAudioCaptureClient, (void**)&pCap);
    if (FAILED(hr)) { printf("service fail %08lx\n", hr); return 1; }
    FILE* out = fopen(argv[1], "wb");
    if (!out) { printf("open out fail\n"); return 1; }
    wav_header(out, 0, wfx->nChannels, wfx->nSamplesPerSec, wfx->wBitsPerSample);
    DWORD written = 0;
    pAC->lpVtbl->Start(pAC);
    DWORD t0 = GetTickCount();
    while ((int)(GetTickCount() - t0) < secs * 1000) {
        Sleep(50);
        UINT32 pklen = 0;
        while (SUCCEEDED(pCap->lpVtbl->GetNextPacketSize(pCap, &pklen)) && pklen) {
            BYTE* data = 0;
            UINT32 frames = 0;
            DWORD flags = 0;
            hr = pCap->lpVtbl->GetBuffer(pCap, &data, &frames, &flags, 0, 0);
            if (FAILED(hr)) break;
            DWORD nbytes = frames * wfx->nBlockAlign;
            if (!(flags & AUDCLNT_BUFFERFLAGS_SILENT) && nbytes) {
                fwrite(data, 1, nbytes, out);
                written += nbytes;
            } else {
                static BYTE zeros[65536];
                DWORD z = nbytes < sizeof(zeros) ? nbytes : sizeof(zeros);
                fwrite(zeros, 1, z, out);   // keep timeline aligned
                written += z;
            }
            pCap->lpVtbl->ReleaseBuffer(pCap, frames);
        }
    }
    pAC->lpVtbl->Stop(pAC);
    fclose(out);
    // fix header sizes
    out = fopen(argv[1], "r+b");
    if (out) {
        fseek(out, 0, SEEK_SET);
        wav_header(out, written, wfx->nChannels, wfx->nSamplesPerSec, wfx->wBitsPerSample);
        fclose(out);
    }
    printf("wrote %lu bytes (%0.1f s) to %s\n", written,
           (double)written / (wfx->nSamplesPerSec * wfx->nBlockAlign), argv[1]);
    return 0;
}
