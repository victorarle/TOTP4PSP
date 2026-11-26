#include <pspkernel.h>
#include <pspdebug.h>
#include <pspdisplay.h>
#include <psputils.h>
#include <pspctrl.h>
#include <pspgu.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "hmac-sha1/src/hmac/hmac.h"
#include "base32/base32.h"
#include "totp.h"
#include "common/callback.h"

#include "intrafont031g/libraries/graphics.h"
#include "intrafont031g/intraFont.h"

#define VERS 1 // version
#define REVS 0 // revision
#define VERSION "0.1.0" // shown in the footer; keep in sync with PSP_EBOOT_TITLE in the Makefile

PSP_MODULE_INFO("TOTP", PSP_MODULE_USER, VERS, REVS);
PSP_MAIN_THREAD_ATTR(PSP_THREAD_ATTR_USER);
PSP_HEAP_THRESHOLD_SIZE_KB(0);

#define printf pspDebugScreenPrintf

enum ALGTYPE
{
    SHA1,
    SHA256,
    SHA512
};


char otpfile[] = "ms0:/PSP/COMMON/OTPAUTH_KEYS";

// ---- Screen layout (480x272) ----
// Font scales are for the PSP's own flash0 fonts; the place to tune how the text looks on the device.
#define CODE_SCALE     2.4f   // code of the selected key (ltn4, bold)
#define NAME_SCALE     1.0f   // name of the selected key (ltn0)
#define NB_SCALE       0.9f   // names of the neighbour keys (ltn0)
#define NB_CODE_SCALE  1.0f   // codes of the neighbour keys (ltn4)
#define SMALL_SCALE    0.9f   // header and footer (ltn8)

#define MARGIN   24           // left and right text margin
#define BAND_Y   96           // glass band of the selected key
#define BAND_H   80
#define FOOT_Y   250          // footer bar
#define ROW_H    30           // neighbour rows, two above and two below the band
#define SLOTS    5            // keys on screen: the selected one and two each side

// Colours are 0xAABBGGRR
#define RGBA(r, g, b, a) ((unsigned int)(a) << 24 | (unsigned int)(b) << 16 | (unsigned int)(g) << 8 | (unsigned int)(r))
#define WHITE_A(a)  RGBA(255, 255, 255, a)
#define BLACK_A(a)  RGBA(0, 0, 0, a)
#define AMBER       RGBA(255, 210, 122, 255)
#define SHADOW      BLACK_A(115)

typedef struct
{
    unsigned int color;
    float x, y, z;
} Vertex;

#define VERTEX_FORMAT (GU_COLOR_8888 | GU_VERTEX_32BITF | GU_TRANSFORM_2D)

// Rectangle with a vertical gradient from `top` to `bottom`, alpha blended
static void
fillRect(float x, float y, float w, float h, unsigned int top, unsigned int bottom)
{
    Vertex *v = (Vertex *)sceGuGetMemory(4 * sizeof(Vertex));
    v[0] = (Vertex){top, x, y, 0};
    v[1] = (Vertex){top, x + w, y, 0};
    v[2] = (Vertex){bottom, x, y + h, 0};
    v[3] = (Vertex){bottom, x + w, y + h, 0};
    sceGuDrawArray(GU_TRIANGLE_STRIP, VERTEX_FORMAT, 4, 0, v);
}

// Part of a ring, clockwise from 12 o'clock, covering `frac` of the circle.
// The colour runs from `inner` at radius r_in to `outer` at r_out; r_in 0 gives a disc.
static void
fillRing(float cx, float cy, float r_in, float r_out, float frac, unsigned int inner, unsigned int outer)
{
    int n = (int)(48 * frac) + 1;
    int i;
    Vertex *v = (Vertex *)sceGuGetMemory(2 * (n + 1) * sizeof(Vertex));
    for (i = 0; i <= n; i++)
    {
        float a = 2 * GU_PI * frac * i / n;
        float s = sinf(a), c = -cosf(a);
        v[2 * i] = (Vertex){outer, cx + r_out * s, cy + r_out * c, 0};
        v[2 * i + 1] = (Vertex){inner, cx + r_in * s, cy + r_in * c, 0};
    }
    sceGuDrawArray(GU_TRIANGLE_STRIP, VERTEX_FORMAT, 2 * (n + 1), 0, v);
}

// Everything behind the text: backdrop, glass band, footer bar
static void
drawBackdrop(void)
{
    const unsigned int top = RGBA(0x05, 0x28, 0x3a, 255);
    const unsigned int mid = RGBA(0x0c, 0x62, 0x73, 255);
    const unsigned int low = RGBA(0x4f, 0xbc, 0xab, 255);

    // intraFont turns these back on whenever it prints
    sceGuDisable(GU_TEXTURE_2D);
    sceGuDisable(GU_DEPTH_TEST);
    sceGuDisable(GU_CULL_FACE);

    fillRect(0, 0, 480, 170, top, mid);
    fillRect(0, 170, 480, 102, mid, low);
    // Soft glow rising from the lower left
    fillRing(90, 260, 0, 210, 1.0f, RGBA(150, 255, 220, 56), RGBA(150, 255, 220, 0));

    // Glass band: brighter upper half, a light edge above and a faint one below
    fillRect(0, BAND_Y, 480, BAND_H / 2, WHITE_A(92), WHITE_A(43));
    fillRect(0, BAND_Y + BAND_H / 2, 480, BAND_H / 2, WHITE_A(26), WHITE_A(26));
    fillRect(0, BAND_Y, 480, 1, WHITE_A(115), WHITE_A(115));
    fillRect(0, BAND_Y + BAND_H - 1, 480, 1, WHITE_A(46), WHITE_A(46));

    fillRect(0, FOOT_Y, 480, 272 - FOOT_Y, BLACK_A(77), BLACK_A(77));
    fillRect(0, FOOT_Y, 480, 1, WHITE_A(56), WHITE_A(56));
}

// Key number `index` of the list, or NULL when there is none
static struct OTPKey *
keyAt(struct OTPKey *head, int index)
{
    if (index < 0) return NULL;
    while (head != NULL && index-- > 0) head = head->next;
    return head;
}

int
main(int argc, char **argv)
{
    pspDebugScreenInit(); 
    setupExitCallback();
    intraFontInit();

    SceCtrlData buttonInput;
    sceCtrlSetSamplingCycle(0);
	sceCtrlSetSamplingMode(PSP_CTRL_MODE_ANALOG);
    
    // Load the fonts in use: sans-serif large regular (0), large bold (4), small regular (8)
    intraFont* ltn[16] = {0};
    char file[40];
    int i;
    for (i = 0; i <= 8; i += 4) {
        sprintf(file,"flash0:/font/ltn%d.pgf",i); 
        ltn[i] = intraFontLoad(file,INTRAFONT_CACHE_ALL);
    }

    if(!ltn[0] || !ltn[4] || !ltn[8]) sceKernelExitGame();

    uint32_t counter = 0;

    printf("Reading OTPauth keys...");
    struct OTPKey *head = readOTPFile(otpfile);

    int selected = 0;                  // index of the key in the band
    unsigned int prevButtons = 0;
    float nameX = MARGIN;              // intraFont keeps the scroll state of a long name in here
    initGraphics();

    while (isRunning())
    {
        // Must be called before any of the intraFont functions
        guStart();

        time_t now = 0;
        sceKernelLibcTime(&now);
        counter = now / TOTP_PERIOD;

        // Up/Down move the selection, one key per press
        sceCtrlPeekBufferPositive(&buttonInput, 1);
        unsigned int pressed = buttonInput.Buttons & ~prevButtons;
        prevButtons = buttonInput.Buttons;
        int step = ((pressed & PSP_CTRL_DOWN) ? 1 : 0) - ((pressed & PSP_CTRL_UP) ? 1 : 0);
        if (step != 0 && selected + step >= 0 && selected + step < num_otp_keys)
        {
            selected += step;
            nameX = MARGIN;
        }

        drawBackdrop();

        // Header: title and position in the list
        intraFontSetStyle(ltn[8], SMALL_SCALE, WHITE_A(217), SHADOW, 0.f, 0);
        intraFontPrint(ltn[8], MARGIN, 19, "TOTP 4 PSP");
        if (head != NULL)
        {
            intraFontSetStyle(ltn[8], SMALL_SCALE, WHITE_A(217), SHADOW, 0.f, INTRAFONT_ALIGN_RIGHT);
            intraFontPrintf(ltn[8], 480 - MARGIN, 19, "%d / %d", selected + 1, num_otp_keys);
        }

        // The selected key sits in the band, two neighbours above and two below it
        int slot;
        for (slot = 0; slot < SLOTS; slot++)
        {
            int offset = slot - SLOTS / 2;
            struct OTPKey *key = keyAt(head, selected + offset);
            if (key == NULL) continue;

            // "123456" is shown as "123 456"; a key that is not supported shows "--- ---", dimmed
            char raw[7];
            char code[8];
            totp_code(key, counter, raw);
            snprintf(code, sizeof(code), "%.3s %s", raw, raw + 3);
            int dim = totp_supported(key) ? 255 : 140;

            if (offset == 0)
            {
                intraFontSetStyle(ltn[0], NAME_SCALE, WHITE_A(255), SHADOW, 0.f, INTRAFONT_SCROLL_LEFT);
                nameX = intraFontPrintColumn(ltn[0], nameX, BAND_Y + 23, 480 - 2 * MARGIN, key->name);
                intraFontSetStyle(ltn[4], CODE_SCALE, WHITE_A(dim), SHADOW, 0.f, 0);
                intraFontPrint(ltn[4], MARGIN - 2, BAND_Y + 68, code);
            }
            else
            {
                // Rows next to the band are brighter than the outer ones
                int alpha = (offset == 1 || offset == -1) ? 192 : 128;
                float y = (offset < 0 ? BAND_Y + offset * ROW_H : BAND_Y + BAND_H + (offset - 1) * ROW_H) + 21;

                intraFontSetStyle(ltn[4], NB_CODE_SCALE, WHITE_A(alpha * dim / 255), SHADOW, 0.f, INTRAFONT_ALIGN_RIGHT);
                float codeWidth = intraFontMeasureText(ltn[4], code);
                intraFontPrint(ltn[4], 480 - MARGIN, y, code);
                // A name that does not fit is cut at the code column
                intraFontSetStyle(ltn[0], NB_SCALE, WHITE_A(alpha), SHADOW, 0.f, INTRAFONT_SCROLL_LEFT);
                intraFontPrintColumn(ltn[0], MARGIN, y, 480 - 2 * MARGIN - codeWidth - 16, key->name);
            }
        }

        // Tell the user why the list is empty instead of a blank screen
        if (head == NULL)
        {
            char nokeys[64];
            sprintf(nokeys, "No keys found in %s", otpfile);
            intraFontSetStyle(ltn[0], NB_SCALE, WHITE_A(255), SHADOW, 0.f, INTRAFONT_SCROLL_LEFT);
            nameX = intraFontPrintColumn(ltn[0], nameX, BAND_Y + BAND_H / 2 + 6, 480 - 2 * MARGIN, nokeys);
        }

        // Footer: the UTC time in use, to compare with a trusted clock; skipped lines; the version
        char clock[48];
        char skipmsg[48] = "";
        totp_clock(now, clock, sizeof(clock));
        if (num_skipped_lines > 0)
            sprintf(skipmsg, "%d line(s) skipped", num_skipped_lines);
        // Shrink the font if the three parts would not fit side by side
        float footScale = SMALL_SCALE;
        const float gap = 14;
        intraFontSetStyle(ltn[8], footScale, WHITE_A(255), SHADOW, 0.f, 0);
        float footWidth = intraFontMeasureText(ltn[8], clock) + gap + intraFontMeasureText(ltn[8], skipmsg)
                        + gap + intraFontMeasureText(ltn[8], "v" VERSION);
        float maxWidth = 480 - 2 * MARGIN;
        if (footWidth > maxWidth) footScale *= maxWidth / footWidth;
        intraFontSetStyle(ltn[8], footScale, WHITE_A(255), SHADOW, 0.f, 0);
        float x = intraFontPrint(ltn[8], MARGIN, FOOT_Y + 16, clock);
        intraFontSetStyle(ltn[8], footScale, AMBER, SHADOW, 0.f, 0);
        intraFontPrint(ltn[8], x + gap, FOOT_Y + 16, skipmsg);
        intraFontSetStyle(ltn[8], footScale, WHITE_A(255), SHADOW, 0.f, INTRAFONT_ALIGN_RIGHT);
        intraFontPrint(ltn[8], 480 - MARGIN, FOOT_Y + 16, "v" VERSION);

        // End drawing
        sceGuFinish();
        sceGuSync(0,0);
        
        // // Swap buffers
        sceDisplayWaitVblankStart();
        flipScreen();
    }

    sceKernelExitGame();

    return 0;
}
