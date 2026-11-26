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
#include "digits.h"

#include "intrafont031g/libraries/graphics.h"
#include "intrafont031g/intraFont.h"

#define VERS 1 // version
#define REVS 0 // revision
#define VERSION "0.2.0" // shown in the footer; keep in sync with PSP_EBOOT_TITLE in the Makefile

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
// The codes do not use them: they come from digits.h, drawn 1:1.
#define NAME_SCALE     1.0f   // name of the selected key (ltn0)
#define NB_SCALE       0.9f   // names of the neighbour keys (ltn0)
#define SMALL_SCALE    0.9f   // header and footer (ltn8)

#define MARGIN   24           // left and right text margin
#define LIST_Y   36           // top of the list: SLOTS keys, the selected one in the glass band
#define BAND_H   80           // height of the band
#define ROW_H    30           // height of every other row
#define SLOTS    5            // keys on screen
#define LIST_H   (BAND_H + (SLOTS - 1) * ROW_H)

// Changing the selection slides the band and the rows instead of jumping: each frame closes
// this fraction of the distance left (60 frames a second; 0.25 settles in about a quarter second)
#define ANIM_RATE 0.25f
#define FOOT_Y   250          // footer bar

// Countdown ring, at the right end of the band
#define RING_X        422
#define RING_IN       22
#define RING_OUT      28
#define LAST_SECONDS  5       // the ring turns amber when this few seconds are left

// The analog stick counts as Up or Down past this distance from its centre (0-127): a worn
// stick drifts, so not much less
#define STICK_DEADZONE 64

// Holding Up or Down repeats the step: after REPEAT_DELAY frames, then every REPEAT_EVERY frames (60 frames a second)
#define REPEAT_DELAY  24
#define REPEAT_EVERY  7

// Colours are 0xAABBGGRR
#define RGBA(r, g, b, a) ((unsigned int)(a) << 24 | (unsigned int)(b) << 16 | (unsigned int)(g) << 8 | (unsigned int)(r))
#define WHITE_A(a)  RGBA(255, 255, 255, a)
#define BLACK_A(a)  RGBA(0, 0, 0, a)
#define AMBER       RGBA(255, 210, 122, 255)
// Text shadow, off. The fonts carry shadow glyphs (BLACK_A(115) would be a soft drop shadow), but
// with PPSSPP's fonts they come out as black bars across the screen, and they are untried on a PSP.
#define SHADOW      0U

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

// The countdown ring: a dark track with `frac` of it lit, shrinking towards 12 o'clock.
// The GU does not smooth edges, so each ring gets a 1 px rim that fades out.
static void
drawRing(float cy, float frac, unsigned int color)
{
    const unsigned int colors[2] = {BLACK_A(77), color};
    const float fracs[2] = {1.0f, frac};
    int i;
    for (i = 0; i < 2; i++)
    {
        unsigned int clear = colors[i] & 0x00FFFFFF;
        fillRing(RING_X, cy, RING_IN - 1, RING_IN, fracs[i], clear, colors[i]);
        fillRing(RING_X, cy, RING_IN, RING_OUT, fracs[i], colors[i], colors[i]);
        fillRing(RING_X, cy, RING_OUT, RING_OUT + 1, fracs[i], colors[i], clear);
    }
}

// Digits drawn from a texture in digits.h, pixel for pixel: intraFont only has the PSP's small
// bitmap fonts, and scaled up for the large code they turn blurry
typedef struct
{
    const unsigned char *texture;
    int texW, texH, stride, cellW, cellH, baseline, height;
} DigitSet;

static const DigitSet largeDigits = {digits_large, DIGITS_LARGE_TEX_W, DIGITS_LARGE_TEX_H, DIGITS_LARGE_STRIDE,
                                     DIGITS_LARGE_CELL_W, DIGITS_LARGE_CELL_H, DIGITS_LARGE_BASELINE, DIGITS_LARGE_HEIGHT};
static const DigitSet smallDigits = {digits_small, DIGITS_SMALL_TEX_W, DIGITS_SMALL_TEX_H, DIGITS_SMALL_STRIDE,
                                     DIGITS_SMALL_CELL_W, DIGITS_SMALL_CELL_H, DIGITS_SMALL_BASELINE, DIGITS_SMALL_HEIGHT};

// 4-bit coverage to white with that much alpha; the vertex colour tints it
static unsigned int __attribute__((aligned(16))) digitClut[16];

// Width of `text` in pixels: every character of DIGITS_CHARS takes a cell, a space half a cell
static int
digitsWidth(const DigitSet *set, const char *text)
{
    int w = 0;
    for (; *text; text++)
        w += (*text == ' ') ? set->cellW / 2 : set->cellW;
    return w;
}

// Draws `text` with the top left corner of its first cell at (x, y)
static void
drawDigits(const DigitSet *set, int x, int y, const char *text, unsigned int color)
{
    typedef struct
    {
        float u, v;
        unsigned int color;
        float x, y, z;
    } TexVertex;

    TexVertex *v = (TexVertex *)sceGuGetMemory(2 * strlen(text) * sizeof(TexVertex));
    int n = 0;
    for (; *text; text++)
    {
        const char *found = strchr(DIGITS_CHARS, *text);
        if (*text != ' ' && found != NULL)
        {
            float u = (found - DIGITS_CHARS) * set->cellW;
            v[n++] = (TexVertex){u, 0, color, x, y, 0};
            v[n++] = (TexVertex){u + set->cellW, set->cellH, color, x + set->cellW, y + set->cellH, 0};
        }
        x += (*text == ' ') ? set->cellW / 2 : set->cellW;
    }

    sceGuEnable(GU_TEXTURE_2D);
    sceGuDisable(GU_DEPTH_TEST);
    sceGuClutMode(GU_PSM_8888, 0, 0xff, 0);
    sceGuClutLoad(2, digitClut);
    sceGuTexMode(GU_PSM_T4, 0, 0, 0);
    sceGuTexImage(0, set->texW, set->texH, set->stride, set->texture);
    sceGuTexFunc(GU_TFX_MODULATE, GU_TCC_RGBA);
    sceGuTexFilter(GU_NEAREST, GU_NEAREST);
    sceGuTexWrap(GU_CLAMP, GU_CLAMP);
    sceGuDrawArray(GU_SPRITES, GU_TEXTURE_32BITF | GU_COLOR_8888 | GU_VERTEX_32BITF | GU_TRANSFORM_2D, n, 0, v);
}

// Everything behind the text: backdrop, glass band at `bandY`, footer bar
static void
drawBackdrop(float bandY)
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
    fillRect(0, bandY, 480, BAND_H / 2, WHITE_A(92), WHITE_A(43));
    fillRect(0, bandY + BAND_H / 2, 480, BAND_H / 2, WHITE_A(26), WHITE_A(26));
    fillRect(0, bandY, 480, 1, WHITE_A(115), WHITE_A(115));
    fillRect(0, bandY + BAND_H - 1, 480, 1, WHITE_A(46), WHITE_A(46));

    fillRect(0, FOOT_Y, 480, 272 - FOOT_Y, BLACK_A(77), BLACK_A(77));
    fillRect(0, FOOT_Y, 480, 1, WHITE_A(56), WHITE_A(56));
}

#ifdef UI_PREVIEW
// Build with CC="psp-gcc -DUI_PREVIEW" to look at the screen in an emulator (see the README):
// the fonts are read from ms0:/font and may be missing (shapes only, no text), a fixed
// sequence of button presses is played, and the screen is saved to
// ms0:/totp4psp-preview-N.png once a second.
#define FONT_DIR "ms0:/font"
static void
previewInput(int frame, SceCtrlData *pad)
{
    pad->Buttons = 0;
    pad->Ly = 128;
    if (frame == 60) pad->Buttons = PSP_CTRL_DOWN;                    // one press
    if (frame >= 120 && frame < 240) pad->Buttons = PSP_CTRL_DOWN;    // held: runs to the last key
    if (frame >= 300 && frame < 330) pad->Ly = 0;                     // stick up a little: a few keys back
}
#else
#define FONT_DIR "flash0:/font"
#endif

// Height of row `i` while the band is at row `sel`. During the slide `sel` falls between two
// rows, and the band's extra height is shared between them.
static float
rowHeight(int i, float sel)
{
    float w = 1 - fabsf(i - sel);
    return ROW_H + (BAND_H - ROW_H) * (w > 0 ? w : 0);
}

// Distance from the top of row 0 down to position `x`, a row number that may fall between rows
static float
rowTop(float x, float sel)
{
    int i, whole = (int)floorf(x);
    float y = 0;
    for (i = 0; i < whole; i++) y += rowHeight(i, sel);
    return y + (x - whole) * rowHeight(whole, sel);
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
    
    // Load the fonts in use: sans-serif large regular (0), small regular (8)
    intraFont* ltn[16] = {0};
    char file[40];
    int i;
    for (i = 0; i <= 8; i += 8) {
        sprintf(file,FONT_DIR "/ltn%d.pgf",i);
        ltn[i] = intraFontLoad(file,INTRAFONT_CACHE_ALL);
    }

#ifndef UI_PREVIEW
    if(!ltn[0] || !ltn[8]) sceKernelExitGame();
#endif
    // Account names are UTF-8 once their %XX escapes are decoded ("Caf%C3%A9")
    intraFontSetEncoding(ltn[0], INTRAFONT_STRING_UTF8);

    uint32_t counter = 0;

    printf("Reading OTPauth keys...");
    struct OTPKey *head = readOTPFile(otpfile);

    int selected = 0;                  // index of the key in the band
    float shownSelected = 0;           // the band as drawn: slides towards `selected`
    float shownFirst = 0;              // the top row as drawn: slides towards the first key on screen
    int heldDir = 0;                   // -1 Up, 1 Down, 0 neither
    int heldFrames = 0;                // frames heldDir has lasted
    float nameX = MARGIN;              // intraFont keeps the scroll state of a long name in here
    // The keys by number, and their codes ("123 456"), computed again when the time step changes
    struct OTPKey **keys = calloc(num_otp_keys + 1, sizeof(*keys));
    char (*codes)[8] = calloc(num_otp_keys + 1, sizeof(*codes));
    if (keys == NULL || codes == NULL) sceKernelExitGame();
    struct OTPKey *key;
    for (i = 0, key = head; key != NULL; key = key->next) keys[i++] = key;
    uint32_t codesCounter = 0;
    int codesValid = 0;
    for (i = 0; i < 16; i++) digitClut[i] = WHITE_A(i * 17);
    sceKernelDcacheWritebackAll();     // the GE reads the textures and the palette from memory
    initGraphics();

    while (isRunning())
    {
        // Must be called before any of the intraFont functions
        guStart();

        // The fraction of the second is only for the ring, read first so that it is never ahead of `now`
        SceKernelTimeval tv = {0};
        sceKernelLibcGettimeofday(&tv, NULL);
        time_t now = 0;
        sceKernelLibcTime(&now);
        counter = now / TOTP_PERIOD;
        int secondsLeft = TOTP_PERIOD - now % TOTP_PERIOD;
        float left = secondsLeft - ((time_t)tv.tv_sec == now ? tv.tv_usec / 1000000.f : 0.f);
        unsigned int ringColor = secondsLeft <= LAST_SECONDS ? AMBER : WHITE_A(255);

        // Up/Down or the analog stick move the selection: one key per push, more while held
        sceCtrlPeekBufferPositive(&buttonInput, 1);
#ifdef UI_PREVIEW
        static int frame = 0;
        previewInput(frame++, &buttonInput);
#endif
        int down = (buttonInput.Buttons & PSP_CTRL_DOWN) || buttonInput.Ly > 128 + STICK_DEADZONE;
        int up = (buttonInput.Buttons & PSP_CTRL_UP) || buttonInput.Ly < 128 - STICK_DEADZONE;
        int dir = down - up;
        heldFrames = (dir == heldDir) ? heldFrames + 1 : 0;
        heldDir = dir;
        int step = 0;
        if (heldFrames == 0 || (heldFrames >= REPEAT_DELAY && (heldFrames - REPEAT_DELAY) % REPEAT_EVERY == 0))
            step = dir;
        if (step != 0 && selected + step >= 0 && selected + step < num_otp_keys)
        {
            selected += step;
            nameX = MARGIN;
        }

        // The list shows SLOTS keys from `first` on. The selected key stays in the middle row
        // unless that would leave rows empty at the start or the end of the list: there the
        // band moves up or down instead.
        int first = selected - SLOTS / 2;
        if (first > num_otp_keys - SLOTS) first = num_otp_keys - SLOTS;
        if (first < 0) first = 0;

        // Slide what is drawn towards that
        shownSelected += (selected - shownSelected) * ANIM_RATE;
        shownFirst += (first - shownFirst) * ANIM_RATE;
        if (fabsf(selected - shownSelected) < 0.01f) shownSelected = selected;
        if (fabsf(first - shownFirst) < 0.01f) shownFirst = first;
        // Screen position of the top of row 0
        float listTop = LIST_Y - rowTop(shownFirst, shownSelected);
        float bandY = head != NULL ? listTop + rowTop(shownSelected, shownSelected) : LIST_Y + (SLOTS / 2) * ROW_H;
        float ringY = bandY + BAND_H / 2;

        drawBackdrop(bandY);
        if (head != NULL) drawRing(ringY, left / TOTP_PERIOD, ringColor);

        // Header: title and position in the list
        intraFontSetStyle(ltn[8], SMALL_SCALE, WHITE_A(217), SHADOW, 0.f, 0);
        intraFontPrint(ltn[8], MARGIN, 19, "TOTP 4 PSP");
        if (head != NULL)
        {
            intraFontSetStyle(ltn[8], SMALL_SCALE, WHITE_A(217), SHADOW, 0.f, INTRAFONT_ALIGN_RIGHT);
            intraFontPrintf(ltn[8], 480 - MARGIN, 19, "%d / %d", selected + 1, num_otp_keys);
        }

        // "123456" is shown as "123 456"; a key that is not supported comes as "------" and shows "--- ---"
        if (!codesValid || counter != codesCounter)
        {
            for (i = 0; i < num_otp_keys; i++)
            {
                char raw[7];
                totp_code(keys[i], counter, raw);
                snprintf(codes[i], sizeof(codes[i]), "%.3s %s", raw, raw + 3);
            }
            codesCounter = counter;
            codesValid = 1;
        }

        // Each row blends between the band style (name, large code) and the row style (smaller
        // name, small code at the right) by how much of the band it has. Rows sliding in or out
        // fade with the part of them outside the list.
        int top = (int)floorf(shownFirst);
        for (i = top - 1; i <= top + SLOTS + 1; i++)
        {
            if (i < 0 || i >= num_otp_keys) continue;
            float y = listTop + rowTop(i, shownSelected);
            float h = rowHeight(i, shownSelected);
            float inside = (fminf(y + h, LIST_Y + LIST_H) - fmaxf(y, LIST_Y)) / h;
            if (inside <= 0) continue;
            if (inside > 1) inside = 1;

            float band = (h - ROW_H) / (BAND_H - ROW_H);   // 1 in the band, 0 in a row
            float d = fabsf(i - shownSelected);             // rows next to the band are brighter
            float alpha = (d < 1 ? 255 - 63 * d : d < 2 ? 192 - 64 * (d - 1) : 128) * inside * inside;
            float dim = totp_supported(keys[i]) ? 1.0f : 0.55f;   // "--- ---" is dimmed
            const char *code = codes[i];
            int codeWidth = digitsWidth(&smallDigits, code);

            if (band < 1)
                drawDigits(&smallDigits, 480 - MARGIN - codeWidth, y + 21 - smallDigits.baseline, code,
                           WHITE_A((int)(alpha * dim * (1 - band) * (1 - band))));   // gone before it reaches the ring
            if (band > 0)
            {
                // Cut at the bottom of the row, so the large code opens and closes with it
                int clipTop = (int)fmaxf(y, 0), clipBottom = (int)fminf(y + h, 272);   // sceGuScissor takes a size
                sceGuScissor(0, clipTop, 480, clipBottom - clipTop);
                drawDigits(&largeDigits, MARGIN - 2, y + 33, code, WHITE_A((int)(alpha * dim * band)));
                sceGuScissor(0, 0, 480, 272);
            }

            // The selected name scrolls if it is too long; any other name is cut at its column
            float width = band >= 0.5f ? RING_X - RING_OUT - 12 - MARGIN : 480 - 2 * MARGIN - codeWidth - 16;
            intraFontSetStyle(ltn[0], NB_SCALE + (NAME_SCALE - NB_SCALE) * band, WHITE_A((int)alpha), SHADOW, 0.f,
                              INTRAFONT_SCROLL_LEFT);
            if (i == selected)
                nameX = intraFontPrintColumn(ltn[0], nameX, y + 21 + 2 * band, width, keys[i]->name);
            else
                intraFontPrintColumn(ltn[0], MARGIN, y + 21 + 2 * band, width, keys[i]->name);
        }

        // Seconds left, inside the ring
        if (head != NULL)
        {
            char secs[4];
            snprintf(secs, sizeof(secs), "%d", secondsLeft);
            drawDigits(&smallDigits, RING_X - digitsWidth(&smallDigits, secs) / 2,
                       ringY - smallDigits.baseline + smallDigits.height / 2, secs, ringColor);
        }

        // Tell the user why the list is empty instead of a blank screen
        if (head == NULL)
        {
            intraFontSetStyle(ltn[0], NB_SCALE, WHITE_A(255), SHADOW, 0.f, 0);
            intraFontPrint(ltn[0], MARGIN, bandY + 34, "No keys found in");
            intraFontPrint(ltn[0], MARGIN, bandY + 58, otpfile);
        }

        // Footer: the UTC time in use, to compare with a trusted clock; skipped lines; the version
        char clock[48];
        char skipmsg[48] = "";
        totp_clock(now, clock, sizeof(clock));
        char *seconds = strstr(clock, "  ");   // drop the seconds left: the ring shows them
        if (seconds != NULL) *seconds = '\0';
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
#ifdef UI_PREVIEW
        if (frame % 60 == 59 && frame < 420)
        {
            sprintf(file, "ms0:/totp4psp-preview-%d.png", frame / 60);
            saveImage(file, getVramDisplayBuffer(), SCREEN_WIDTH, SCREEN_HEIGHT, PSP_LINE_SIZE, 0);
        }
        // A few frames of the slide after the single press (band moves) and during the hold (rows scroll)
        if ((frame > 60 && frame <= 68) || (frame > 144 && frame <= 152))
        {
            sprintf(file, "ms0:/totp4psp-slide-%03d.png", frame);
            saveImage(file, getVramDisplayBuffer(), SCREEN_WIDTH, SCREEN_HEIGHT, PSP_LINE_SIZE, 0);
        }
#endif
    }

    sceKernelExitGame();

    return 0;
}
