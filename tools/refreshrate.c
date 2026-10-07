// refreshrate.c — print current display refresh rate
#include <windows.h>
#include <stdio.h>
int main(void) {
    DEVMODEA dm; ZeroMemory(&dm, sizeof(dm)); dm.dmSize = sizeof(dm);
    if (EnumDisplaySettingsA(NULL, ENUM_CURRENT_SETTINGS, &dm))
        printf("%lux%lu @ %luHz\n", dm.dmPelsWidth, dm.dmPelsHeight, dm.dmDisplayFrequency);
    else printf("EnumDisplaySettings fail\n");
    return 0;
}
